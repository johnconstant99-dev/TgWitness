"use strict";
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
let workspaceSafety;
const workspaceSafetyReady=import('./core/workspace-safety.js?v=1').then(({createWorkspaceSafety})=>{
  workspaceSafety=createWorkspaceSafety({state,find:$,tr,avatar:avatarNode,switchProfile,refreshStatus,confirm:askConfirm});
  window.TgWitnessWorkspace=workspaceSafety;
});
let accountState;
let boardView;
const boardReady=import('./views/board.js?v=2').then(({createCaseBoard})=>{
  boardView=createCaseBoard({root:$('view-board'),state,json,tr,trn,node,toast,may,download,media:mediaNode,
    openEvidence:async(event,range)=>{
      const revision=state.workspaceRevision;
      state.boardSlice=null;state.boardAdded=false;state.filter='';state.source='';state.search='';state.eventSince='';state.eventUntil='';state.eventSystem=true;
      state.eventBefore=event.seq+51;state.cursor=null;
      await navigate('observations');
      if(revision!==state.workspaceRevision)return;
      await openDetail(event);
      const text=$('detail-content').querySelector('.message-text');
      if(range&&text){
        const raw=event.payload?.[range.field];
        if(text.textContent===raw){const chars=Array.from(raw);text.replaceChildren(document.createTextNode(chars.slice(0,range.start).join('')),
          node('mark','',chars.slice(range.start,range.start+range.length).join('')),document.createTextNode(chars.slice(range.start+range.length).join('')));}
        text.before(node('p','hint',tr('Highlight is tied to this saved version.')));
      }
      const row=$('events-body').querySelector('[data-seq="'+event.seq+'"]');if(row){row.scrollIntoView({block:'center'});replay(row,'board-pulse',3000);}
    },
    openSlice:async card=>{
      state.boardSlice=card.id;state.boardAdded=false;state.filter='';state.source='';
      state.search='';state.eventSince=card.query.from||'';state.eventUntil=card.query.to||'';state.eventSystem=true;
      state.eventBefore=state.eventAfter=state.cursor=null;
      await navigate('observations');
      let badge=$('board-slice-context');if(!badge){badge=node('div','board-slice-context hint');badge.id='board-slice-context';viewQuery('observations','.card-heading').append(badge);}
      badge.replaceChildren(node('span','',tr('Slice: {title}',{title:card.title||card.id.slice(0,8)})));
      const open=node('button','text-link',tr('Explore exact slice'));open.type='button';open.addEventListener('click',()=>boardView.explore(card.id));badge.append(open);
      const toggle=node('label','check-label'),input=node('input');input.type='checkbox';toggle.append(input,node('span','',tr('Show records added since bookmark')));
      input.addEventListener('change',()=>{state.boardAdded=input.checked;state.eventBefore=state.eventAfter=state.cursor=null;refreshEvents();window.TgWitnessRouter?.record();});badge.append(toggle);
    }});
  window.TgWitnessBoard=boardView;
  const save=node('button','secondary small',tr('Save as slice'));save.type='button';save.id='journal-to-slice';
  save.addEventListener('click',()=>boardView.sliceDialog({chat_id:state.source?Number(state.source):undefined,chat_ids:state.source?undefined:(state.status?.targets||[]).map(item=>item.chat_id),from:state.eventSince||undefined,to:state.eventUntil||undefined,kinds:state.filter?state.filter.split(','):'all',search:state.search,hide_system:!state.eventSystem}));
  viewQuery('observations','.card-heading').append(save);
  const slice=node('button','quiet small',tr('Slice by time'));slice.type='button';slice.id='chat-to-slice';slice.addEventListener('click',()=>boardView.sliceDialog({chat_id:state.chat}));viewQuery('chats','.chat-toolbar').append(slice);
});
let settingsHub;
const settingsHubReady=import('./views/settings-hub.js?v=layout1-wizard1').then(({createSettingsHub})=>{
  const authCard=$('credentials-form').closest('.auth-card');
  const catalog=()=>panelQueries('input[id],select[id],textarea[id]').filter(el=>!el.closest('#gate,#view-settings,#view-first-run')).map(el=>{
    const root=[...panelRoots].find(([,r])=>r.contains(el));
    const view=root?.[0]||'connection';
    const text=el.labels?.[0]?.textContent?.trim()||el.getAttribute('aria-label')||el.id;
    el.dataset.level=el.dataset.level||(['parameters','integrations','system-log'].includes(view)?'expert':'standard');
    const form=el.closest('form')?.id, extra=el.closest('.extra-panel')?.id.replace('extras-','');
    return {key:el.id,id:el.id,label:text,view,level:el.dataset.level,extra,form};
  });
  settingsHub=createSettingsHub({root:$('view-settings'),wizardRoot:$('view-first-run'),state,json,tr,node,toast,navigate,askConfirm,$,refreshStatus,
    staleView:()=>new StaleView(),
    language:LANG,languages:LANGUAGES,authCard:()=>authCard,authMethod:setAuthMethod,catalog,
    loadSettingsForm:id=>({'alerts-form':loadAlerts,'replica-form':loadReplica,'evidence-form':loadEvidence}[id])(),
    openExtra:async id=>{await loadExtras();selectExtra(id);},changeLanguage:setLanguage,
    stateBadge,healthLines:collectorLines,healthNames:healthPartNames,record:options=>window.TgWitnessRouter?.record({},options||{}),trn,
    openConnection:async preset=>{await navigate('connection');await connectionViewReady;connectionView.preset(preset);},
    applyPreferences:p=>{
      for(const el of panelQueries('[data-mode-locked]'))el.removeAttribute('data-mode-locked');
      for(const el of panelQueries('.mode-lock'))el.hidden=true;
      panelTime?.setZone(p.timezone);updateTimes();
      const choice=$('time-zone');if(choice){if(![...choice.options].some(o=>o.value===p.timezone))choice.add(new Option(p.timezone,p.timezone));choice.value=p.timezone;}
      window.tgwApplyTheme?.(p.theme);
    }});
  window.tgwSaveLanguage=async language=>{if(state.token)await settingsHub.refreshPreferences({language});};
  document.addEventListener('tgwitness:theme',event=>{if(state.token)settingsHub.refreshPreferences({theme:event.detail}).catch(e=>toast(e.message,true));});
  catalog();
});
let connectionView;
const connectionViewReady=import('./views/connection.js?v=2').then(({createConnectionView})=>{
  connectionView=createConnectionView({root:$('connect-guide'),tr,json,state,refreshStatus,askConfirm});
});
const accountStateReady=import('./components/account-state.js?v=1').then(module=>{accountState=module.accountState;});
let disclosurePreview;
const disclosurePreviewReady=import('./views/disclosure-preview.js?v=2').then(({createDisclosurePreview})=>{
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
        if(name==='settings'||name==='first-run')settingsHub?.leave();
        top=window.scrollY;scrolls=[root,...root.querySelectorAll('*')].filter(element=>element.scrollTop).map(element=>[element,element.scrollTop]);
        if(name==='connection'){window.TgWitnessProxies?.stop?.();connectionView?.leave();}
        if(name==='integrations'){window.TgWitnessIntegrations?.clear();window.TgWitnessWebhooks?.clear();}
        if(name==='sealed')window.TgWitnessCaptureStory?.pause?.();
        if(name==='parameters')parametersView?.leave();
        if(name==='evidence'){exportsView?.leave();reportSelection?.leave();}
        if(name==='system-log')systemLogView?.leave();
        if(name==='system-map')systemMapView?.leave();
        if(name==='observations')window.TgWitnessJournal?.leave();
        if(name==='board')boardView?.leave();
        if(name==='topology')topologyView?.leave();
      },
      resetSession(){top=0;scrolls=[];viewContexts.delete(name);resetViewContent(name);},
    });
  }
});
function resetViewContent(view){
  if(view==='board')boardView?.reset();
  if(view==='topology')topologyView?.resetSession();
  const root=panelRoots.get(view);for(const form of root.querySelectorAll('form'))form.reset();
  for(const field of root.querySelectorAll('input,textarea'))if(!field.form){field.value=field.defaultValue;field.checked=field.defaultChecked;}
  if(view==='connection'){networkLoadedFor=null;policyOutsideDirty=false;policyFormDirty=false;state.policy=null;connectionView?.reset();}
  if(view==='sources'){state.scope=null;state.scopeDirty=false;state.recheckDirty=false;}
  if(view==='parameters')parametersView?.resetSession();
  if(view==='evidence'){exportsView?.resetSession();resetAccountExport();}
  if(view==='accounts')accountsView?.resetSession();
  if(view==='group')groupView?.reset();
  if(view==='witness'){setupView?.resetSession();state.evidenceDirty=false;state.replicaDirty=false;state.alertsDirty=false;state.githubDirty=false;}
  if(view==='chats')chatListView?.resetSession();
  if(view==='sealed')window.TgWitnessCapture?.reset();
  if(view==='system-log')systemLogView?.resetSession();
  if(view==='system-map')systemMapView?.resetSession();
  if(view==='access'){accessView?.resetSession();accessFormVersion++;adminLimitsVersion++;accessFormReady=false;adminLimitsReady=false;adminLimitsDirty=false;accessLoadSerial++;
    state.access=null;state.accessEdit=null;state.accessChats={};state.consoleAfter=0;show('access-new',false);}
  if(view==='observations'){state.boardSlice=null;state.boardAdded=false;$('board-slice-context')?.remove();window.TgWitnessJournal?.reset();}
  const clear={observations:['events-body'],chats:['chats-list','chat-feed','chat-people','chat-about'],accounts:['accounts-list','fleet-groups'],
    access:['access-list','access-sessions-list','access-token'],'system-log':['access-console'],
    connection:['profiles-list'],witness:['witness-list','github-result','cloud-health','alerts-saved','evidence-status','replica-status'],
    integrations:['webhook-list','webhook-history','webhook-chats']}[view]||[];
  for(const id of clear)$(id)?.replaceChildren();
}
async function loadPanelView(view){
  if(view==='topology'){await topologyReady;await topologyView.enter();return;}
  if(view==='system-map'){await systemMapReady;await systemMapView.enter();return;}
  if(view==='board'){await boardReady;await boardView.load();return;}
  if(view==='settings'||view==='first-run'){await settingsHubReady;await settingsHub.load();}
  else if(view==='start')renderWorkflowControls();
  else if(view==='sources'){await sourcesReady;sourcesView.enter();renderTargets();await loadScope();}
  else if(view==='witness')await loadExtras();
  else if(view==='parameters')await loadParameters();
  else if(view==='accounts'){renderAccounts();await loadProfiles();}
  else if(view==='group'){await groupViewReady;await loadProfiles();await groupView.load(state.groupId);}
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
  else if(view==='connection'){await loadProfiles();if(!state.status.demo)await loadPolicy();await connectionViewReady;await connectionView.enter();}
}
let routerTask=null;
function routeSnapshot(){return {view:state.drawerSeq!==null?"observations":state.view,workspace:state.profile,
  slice:state.boardSlice||null,added:!!state.boardAdded,
  chatId:state.view==="chats"?state.chat:null,seq:state.drawerSeq,kind:state.filter,source:state.source,q:state.search,
  since:state.eventSince,until:state.eventUntil,system:state.eventSystem,before:state.eventBefore,extra:state.extra||null,section:state.parameterSection||null,
  step:state.view==="first-run"?settingsHub?.step||null:null,group:state.view==="group"?state.groupId:null};}
function ensureRouter(){
  if(!routerTask)routerTask=import("./router.js?v=9").then(({createRouter})=>{
    window.TgWitnessRouter=createRouter({snapshot:routeSnapshot,ready:()=>!!state.me&&!$("workspace").hidden,
      error:message=>toast(tr(message),true),apply:applyRouteToPanel});return window.TgWitnessRouter;
  });
  return routerTask;
}
async function applyRouteToPanel(route,current){
  if(!state.profiles.some(profile=>profile.id===route.workspace&&!profile.error_type))throw new Error(tr("Unknown workspace."));
  if(state.profile!==route.workspace&&await switchProfile(route.workspace,{history:false})===false){
    if(current())window.TgWitnessRouter?.record({}, {replace:true});
    return;
  }
  if(!current())return;
  closeDetail({history:false});
  state.filter=route.kind;state.source=route.source;state.search=route.q;state.eventSince=route.since;state.eventUntil=route.until;
  state.eventSystem=!!route.system;
  state.boardSlice=route.slice||null;state.boardAdded=!!route.added;
  state.eventBefore=route.before??null;
  $("event-search").value=state.search;fillSourceSelect("source-filter",state.source,true);
  viewQueries("observations","[data-filter]").forEach(button=>button.classList.toggle("active",button.dataset.filter===state.filter));
  if(route.view==="chats"&&route.chatId!==null&&route.chatId!==state.chat)beginChat(route.chatId);
  if(route.view==="group")state.groupId=route.group;
  navigate(route.view,{history:false,load:false});
  const view=state.view;
  if(view==='topology'){await topologyReady;if(current())await topologyView.enter();return;}
  if(view==='system-map'){await systemMapReady;if(current())await systemMapView.enter();return;}
  if(view==='board'){await boardReady;await boardView.load();return;}
  if(view==='settings'||view==='first-run'){await settingsHubReady;await settingsHub.load(route.step);}
  else if(view==="chats"){
    await refreshChats(false,route.chatId);
    if(current()&&route.chatId!==null){
      if(state.chat!==route.chatId)await openChat(route.chatId,{history:false});
      else loadChatProfile().catch(()=>{});
    }
  }
  else if(view==="observations"){await refreshEvents();if(current()&&route.seq)await openRecord(route.seq,{history:false});}
  else if(view==="sources"){await sourcesReady;sourcesView.enter();renderTargets();await loadScope();}
  else if(view==="parameters"){
    await loadParameters();if(current()){state.parameterSection=route.section;if(route.section)parametersView?.selectSection(route.section,{record:false});}
  }else if(view==="accounts")await loadProfiles();
  else if(view==="group"){await groupViewReady;await loadProfiles();if(current())await groupView.load(route.group);}
  else if(view==="connection"){await loadProfiles();if(current()&&!state.status.demo)await loadPolicy();await connectionViewReady;if(current())await connectionView.enter();}
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
  'board.read':[tr('Read Case Board'),tr('Read team notes within the permitted chats.')],
  'board.write':[tr('Write Case Board'),tr('Create bookmarks, highlights, slices and comments.')],
  'board.manage':[tr('Manage Case Board'),tr('Manage collections, final statuses and other participants’ cards.')],
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
  "secret_chat.settings": [tr("Pseudo-secret settings changed"), "settings", "system"],
  "secret_chat.requested": [tr("Pseudo-secret requested"), "lock", "system"], "secret_chat.accepted": [tr("Pseudo-secret accepted"), "lock", "system"],
  "secret_chat.accept_failed": [tr("Pseudo-secret not accepted"), "alert", "coverage"], "secret_chat.ready": [tr("Pseudo-secret established"), "lock", "system"],
  "secret_chat.message": [tr("Pseudo-secret message"), "message", ""], "secret_chat.file": [tr("Pseudo-secret file preserved"), "clip", ""],
  "secret_chat.file_failed": [tr("Pseudo-secret file not saved"), "alert", "coverage"], "secret_chat.file_deferred": [tr("Pseudo-secret file queued"), "alert", "coverage"],
  "secret_chat.action": [tr("Pseudo-secret notice"), "lock", ""],
  "secret_chat.closed": [tr("Pseudo-secret ended"), "lock", "system"], "secret_chat.decrypt_failed": [tr("Pseudo-secret message refused"), "alert", "coverage"],
  "secret_chat.send_failed": [tr("Pseudo-secret message rejected"), "alert", "coverage"],
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
  "account.initialized": [tr("Account initialized"), "account", "system"],
  "account.connection_checked": [tr("Client connection checked"), "link", "system"],
  "account.signed_out": [tr("Signed out of Telegram"), "account", "system"], "target.changed": [tr("Source selection changed"), "sources", "system"],
  "account.sessions": [tr("Account sessions recorded"), "account", "system"],
  "account.session_ended": [tr("Account session ended"), "account", "system"],
  "account.password_changed": [tr("Two-step password changed"), "lock", "system"],
  "account.forgotten": [tr("Session forgotten on this computer"), "account", "system"],
  "account.restricted": [tr("Telegram restricted the account"), "alert", "coverage"],
  "account.restriction_expired": [tr("Account restriction ended"), "refresh", "system"],
  "account.read_only": [tr("Read-only for Telegram actions changed"), "lock", "system"],
  "connection.opened": [tr("Connected to Telegram"), "link", "system"],
  "connection.closed": [tr("Disconnected from Telegram"), "link", "system"],
  "source.added": [tr("Source added"), "plus", "system"],
  "source.access_lost": [tr("Access to the chat lost"), "alert", "coverage"],
  "source.access_restored": [tr("Access to the chat restored"), "refresh", "system"],
  "deletion.batch": [tr("Messages deleted together"), "trash", "delete"],
  "history.cleared": [tr("Messages deleted together"), "trash", "delete"],
  "history.unparsed": [tr("Messages in a format this version cannot read"), "question", "coverage"],
  "message.unpinned": [tr("Message unpinned"), "edit", "edit"],
  "actor.profile_changed": [tr("Profile changed"), "account", "member"],
  "actor.avatar_saved": [tr("Profile photo saved"), "account", "member"],
  "actor.avatar_removed": [tr("Profile photo removed"), "account", "member"],
  "telegram.takeout_unavailable": [tr("Fast export session unavailable"), "clock", "system"],
  "chat_export.started": [tr("Chat export started"), "export", "system"],
  "chat_export.completed": [tr("Chat export completed"), "export", "system"],
  "chat_export.interrupted": [tr("Chat export interrupted"), "alert", "coverage"],
  "network.tunnel_unavailable": [tr("Local tunnel unavailable"), "alert", "coverage"],
  "profile.renamed": [tr("Workspace renamed"), "settings", "system"],
  "capture.changed": [tr("Attachment settings changed"), "settings", "coverage"], "clock.discontinuity": [tr("Clock change detected"), "clock", "coverage"],
  "connection.retry": [tr("Reconnecting to Telegram"), "refresh", "system"], "connection.retry_failed": [tr("Reconnect attempt failed"), "alert", "coverage"],
  "telegram.backoff": [tr("Telegram rate limit"), "clock", "coverage"], "export.failed": [tr("Export failed"), "alert", "coverage"],
  "network.changed": [tr("Connection route changed"), "link", "system"], "network.probe": [tr("Connection test"), "link", "system"],
  "network.route_assigned": [tr("Proxy assigned"), "link", "system"], "network.route_rotated": [tr("Proxy replaced"), "refresh", "coverage"],
  "network.route_unavailable": [tr("No working proxy"), "alert", "coverage"],
  "network.route_fallback": [tr("Connected directly without a proxy"), "alert", "coverage"],
  "network.policy_changed": [tr("IP protection changed"), "shield", "system"],
  "network.connection_applied": [tr("Checked connection applied"), "link", "system"],
  "network.connection_checked": [tr("Connection checked"), "link", "system"],
  "network.connection_failed": [tr("Connection change not applied"), "alert", "coverage"],
  "network.tunnel_control": [tr("Local tunnel started or stopped"), "link", "system"],
  "settings.changed": [tr("Settings changed"), "settings", "system"],
  "settings.collection_pending": [tr("Recording waits for a working connection"), "alert", "coverage"],
  "sources.selected": [tr("Chats to record chosen"), "sources", "system"],
  "group.settings_inherited": [tr("Group settings taken"), "settings", "system"],
  "profile_group.settings_changed": [tr("Group settings changed"), "settings", "system"],
  "profile_group.settings_adopted": [tr("Accounts returned to the group settings"), "settings", "system"],
  "profile_group.settings_failed": [tr("Group settings not applied"), "alert", "coverage"],
  "profile_group.migrated": [tr("Group shares its copied settings"), "settings", "system"],
  "profile_group.exported": [tr("Group exported"), "export", "system"],
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
  "workspace.mode_changed": [tr("Protection mode changed"), "shield", "system"],
  "handover.exported": [tr("Handover extract prepared"), "export", "system"],
};
function secretActionText(p){
  const d=p.details||{},n=(d.random_ids||[]).length;
  return {DeleteMessages:tr("The other side deleted {n} messages; TgWitness keeps them.",{n}),FlushHistory:tr("The other side cleared the history; TgWitness keeps it."),
    SetMessageTTL:tr("Timer set to {n} s",{n:d.ttl_seconds??0}),ScreenshotMessages:tr("The other side took a screenshot."),
    ReadMessages:tr("The other side read {n} messages.",{n}),Typing:tr("The other side is typing.")}[p.action]||p.action;
}
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
  if(target.getAttribute("aria-expanded")==="true")return;
  hideTooltip();tooltipTarget=target;tooltip.textContent=target.title;tooltip.hidden=false;
  if(!target.textContent.trim()&&!target.getAttribute("aria-label"))target.setAttribute("aria-label",target.title);
  target.setAttribute("aria-describedby",[target.getAttribute("aria-describedby"),tooltip.id].filter(Boolean).join(" "));
  const rect=target.getBoundingClientRect();tooltip.style.left=Math.max(8,Math.min(rect.left,innerWidth-tooltip.offsetWidth-8))+"px";
  tooltip.style.top=(rect.bottom+tooltip.offsetHeight+8<innerHeight?rect.bottom+6:Math.max(8,rect.top-tooltip.offsetHeight-6))+"px";
}
document.addEventListener("pointerover",showTooltip);document.addEventListener("focusin",showTooltip);
document.addEventListener("pointerout",event=>{if(tooltipTarget&&!tooltipTarget.contains(event.relatedTarget))hideTooltip();});
document.addEventListener("focusout",hideTooltip);document.addEventListener("keydown",event=>{if(event.key==="Escape")hideTooltip();});
document.addEventListener("scroll",hideTooltip,true);document.addEventListener("pointerdown",hideTooltip,true);
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
  visible_in_dialogs:tr("visible in dialogs"),receiving_updates:tr("receiving updates, not in the chat list"),access_unconfirmed:tr("access unconfirmed"),access_lost:tr("access lost: removed or no longer readable"),
  not_in_dialogs:tr("not found among the account's chats"),beyond_dialog_limit:tr("beyond the chats listed for this account"),public_username:tr("public username"),
  private_or_unlisted:tr("private or unlisted"),creator:tr("creator"),administrator:tr("administrator"),
  member_or_unknown:tr("member or unknown"),unknown:tr("unknown"),messages:tr("messages"),edits:tr("edits"),
  deletions:tr("deletions"),reactions:tr("reactions"),membership:tr("membership"),profiles:tr("profile changes"),presence:tr("online statuses")};
const termText=value=>termLabels[value]??String(value??"").replaceAll("_"," ");
function actionOwner(){
  const profile=state.profile,token=state.token,revision=state.workspaceRevision;
  return {profile,token,revision,current:()=>profile===state.profile&&token===state.token&&revision===state.workspaceRevision};
}
async function ownedDialog(method,...args){
  const owner=actionOwner(),result=await window.TgWitnessDialogs[method](...args);
  return owner.current()?result:null;
}
const askConfirm=(message,options)=>ownedDialog('confirm',message,options);
const askText=(message,options)=>ownedDialog('prompt',message,options);
const askTyped=(message,expected,options)=>ownedDialog('typed',message,expected,options);
const MEDIA_TYPE_LABELS={photo:"Photos",video:"Videos",animation:"GIFs & animations",video_note:"Round video messages",
  voice:"Voice messages",audio:"Music & audio",sticker:"Stickers",document:"Files & documents"};
let panelTime;
const timeReady=import("./core/time.js?v=1").then(({createTimeFormatter})=>{
  let zone="UTC";try{zone=localStorage.getItem("tgwitness-time-zone")||"UTC";}catch{}
  panelTime=createTimeFormatter({locale:LANG,translate:tr,zone});
  const label=node("label","language-pick time-zone-pick"),select=node("select");
  select.id="time-zone";select.setAttribute("aria-label",tr("Display time"));
  select.append(new Option(tr("UTC"),"UTC"),new Option(tr("Local time"),"local"));select.value=panelTime.zone;
  label.append(node("span","",tr("Time")),select);document.querySelector(".sidebar .preferences").prepend(label);
  select.addEventListener("change",()=>{
    settingsHub?.refreshPreferences({timezone:select.value==='local'?Intl.DateTimeFormat().resolvedOptions().timeZone:select.value}).catch(e=>toast(e.message,true));
    panelTime.setZone(select.value);try{localStorage.setItem("tgwitness-time-zone",panelTime.zone);}catch{}
    if(state.view==="chats"&&state.chat!==null){const feed=$("chat-feed"),top=feed.scrollTop;renderChatFeed();feed.scrollTop=top;}
    updateTimes();window.dispatchEvent(new CustomEvent("tgwitness:time-zone",{detail:{zone:panelTime.zone}}));
  });
});
const shellReady=import("./components/shell.js?v=layout1").then(({createResponsiveShell})=>createResponsiveShell({node,icon,tr}));
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
      ['github-form',value=>state.githubDirty=value]].map(([id,setDirty])=>({form:$(id),setDirty,
        onDiscard:id==='report-form'?discardReportDraft:undefined}))});
  $("report-form").querySelector('.form-draft-bar').append($("report-open-downloads"));
});
function fmtTime(value,options){return panelTime?.fmtTime(value,options)??tr("No data");}
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
let qrPending=null,importExpectedId=null,importClientProfile=null,importFormats=[],importTwoFactor="",accountImportRevision=0,authMethod="phone";
let accessStarted=false;
class StaleView extends Error {constructor(){super("");this.name="StaleView";}}
function toast(message, error=false) { if(!message)return;const n = $("toast"); n.textContent = message; n.classList.toggle("error", error); show("toast", true); clearTimeout(toastTimer); toastTimer = setTimeout(() => leave("toast"), error ? 9000 : 5000); }
async function api(path, body, options={}) {
  const cancellingLogin=/^auth\/qr\/[A-Za-z0-9_-]+\/cancel$/.test(path);
  if(state.me&&!$("workspace").hidden&&!cancellingLogin&&!['access/me','profiles','access/logout'].includes(path))workspaceSafety?.assert();
  const revision=state.workspaceRevision;
  const {root=false,profile=state.profile,token=state.token,allowStale=false,...fetchOptions}=options;
  if(body?.enabled&&['evidence','replica','alerts'].includes(path)&&state.me?.admin){
    const current=await json('settings',undefined,{profile,token});
    if(!current.values.outside){
      if(!await askConfirm(tr('This feature needs external requests. Allow them?')))throw new Error(tr('Cancelled'));
      if(revision!==state.workspaceRevision||token!==state.token)throw new StaleView();
      await json('settings/edit',{key:'outside',value:true,revision:current.revision},{profile,token});
    }
  }
  if(!allowStale&&revision!==state.workspaceRevision)throw new StaleView();
  const prefix=root||profile==="default" ? "/api/" : "/profiles/"+encodeURIComponent(profile)+"/api/";
  const deadline=path==='status'?AbortSignal.timeout(15000):null;
  const requestSignal=deadline?(fetchOptions.signal?AbortSignal.any([deadline,fetchOptions.signal]):deadline):fetchOptions.signal;
  let response;try{response = await fetch(prefix + path, {method: body === undefined ? "GET" : "POST",
    headers: {Authorization: "Bearer " + token, ...(body !== undefined ? {"Content-Type":"application/json"} : {}),
      ...(path.startsWith("auth/")||path==="profiles/import"?{"X-TgWitness-System-Language":navigator.language}:{})},
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
    if (typeof detail === "object") detail = tr(detail.message) + (detail.retry_after ? " " + tr("Retry after {n} seconds.", {n: detail.retry_after}) : "") + (detail.error_id ? " " + tr("Error ID for the panel log: {id}", {id: detail.error_id}) : "");
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
    if(['auth-continue','import-account'].includes(button.id))window.TgWitnessAccountImport?.syncControls();
    if(button.id==="chat-send"||button.id==="chat-preview-button"||button.matches(".msg-button button"))renderComposer();} }
}
function lock() {
  settingsHub?.reset();
  state.workflow=null;state.exportTask='journal';
  window.TgWitnessRouter?.invalidate();
  viewHost?.resetSession();formControls?.reset();connectionNotice?.clear();state.permissionsStamp=null;
  state.events=[];state.chats=[];state.chatsLoading=false;state.chatsError=false;state.chatMessages=[];state.chatInfo=null;state.chat=null;state.parameters=null;
  sourcesView?.resetSession();
  parametersView?.resetSession();
  resetChatExportTools();
  resetReportSettings();
  window.dispatchEvent(new Event("tgwitness:lock"));
  $("quick-dialog").close();window.TgWitnessDialogs?.closeAll();modesUI?.reset();
  $("workspace").inert=false;
  resetInteractions();
  const token=state.token,qrCancelled=cancelQR();
  state.workspaceRevision++;state.monitoringDirty=false;state.captureDirty=false;state.parametersDirty=false;clearVerification();

  if(token.startsWith("tgws_"))qrCancelled.finally(()=>fetch("/api/access/logout",{method:"POST",headers:{Authorization:"Bearer "+token}}).catch(()=>{}));
  state.me=null;state.access=null;state.accessNames={};state.accessEdit=null;state.accessChats={};state.consoleAfter=0;$("access-console").textContent="";
  $("access-token").textContent="";show("access-new",false);
  state.token=""; sessionStorage.removeItem("tgwitness-token"); closeDetail({history:false});
  $("export-dialog").close("cancel");stopExportPoll();clearTimeout(multiPoll);multiPoll=null;state.multiChecked=false;
  clearSecrets();resetWitnessSetup();selectExtra(null);
  $("panel-token").value=""; show("workspace",false); show("gate",true);
}
async function bootstrapSettings(options={}) {
  const revision=state.workspaceRevision,token=state.token,initialRoute=location.href;
  await settingsHubReady;
  if(revision!==state.workspaceRevision||token!==state.token)return;
  try { await settingsHub.bootstrap({...options,openFirstRun:options.openFirstRun!==false&&location.href===initialRoute}); }
  catch(error) { if(!(error instanceof StaleView))toast(error.message,true); }
}
function unlockFailed(error) {
  if(error instanceof StaleView)return;
  if(error.status===401||error.status===403){
    lock();$('login-error').textContent=error.message;return;
  }
  const message=$('login-error');message.textContent=error.message||tr('Panel connection unavailable');
  if(!state.token)return;
  sessionStorage.setItem('tgwitness-token',state.token);
  window.TgWitnessLive?.stop();show('workspace',false);show('gate',true);
  const retry=node('button','secondary',tr('Retry'));retry.id='bootstrap-retry';retry.type='button';
  retry.addEventListener('click',()=>{retry.disabled=true;location.reload();});
  message.append(document.createElement('br'),retry);
}
async function unlock() {
  accessStarted=true;
  await Promise.all([timeReady,shellReady,viewReady,formsReady,connectionReady,chatListReady,accountStateReady,disclosurePreviewReady,workspaceSafetyReady]);
  const router=await ensureRouter(),requested=router.parse();
  state.me = await json("access/me",undefined,{root:true});
  state.accessNames=state.me?.admin?(await json("access",undefined,{root:true}).catch(()=>({}))).names||{}:{};
  await loadProfiles();
  if(state.profiles.some(profile=>profile.id===requested.workspace&&!profile.error_type))state.profile=requested.workspace;
  if(!state.profiles.some(p=>p.id===state.profile && !p.error_type))
    state.profile=state.profiles.find(p=>!p.error_type)?.id||"default";
  if(requested.error||requested.explicit&&requested.workspace!==state.profile)throw new Error(tr('Unknown workspace.'));
  $('profile-select').value=state.profile;
  if(!new URL(location.href).searchParams.has('ws')){
    const initialURL=new URL(location.href);initialURL.searchParams.set('ws',state.profile);history.replaceState(history.state,'',initialURL);
  }
  state.status = await json("status");
  workspaceSafety?.acceptStatus(state.status);
  applyAccess();
  if(!state.opened&&!requested.explicit){
    state.view=state.status.demo||state.status.targets?.length&&state.status.stats.total?'chats':viewAllowed('start')?'start':'chats';
  }
  if(!viewAllowed(state.view))state.view="chats";
  state.opened=true;
  sessionStorage.setItem("tgwitness-token", state.token);
  show("gate",false); show("workspace",true); $("panel-token").value="";
  navigate(state.view,{history:false});

  renderStatus(); setAuthStep(accountSignedIn() ? "authorized" : "credentials");
  loadNotifications().catch(()=>{});
  await router.start();
  await bootstrapSettings({openFirstRun:!requested.explicit});
}
$("unlock-form").addEventListener("submit", async event => {
  event.preventDefault(); $("login-error").textContent="";
  const button = event.submitter; button.disabled=true;
  try {

    const entered=$("panel-token").value.trim();
    state.token=(await json("access/login",{token:entered},{root:true,token:""})).session;
    await unlock();
  } catch (e) { unlockFailed(e); } finally { button.disabled=false; }
});
function may(permission){return !!state.me&&(state.me.admin||state.me.permissions.includes(permission));}

function viewAllowed(view){
  if(view==='topology')return !!state.me?.admin;
  if(view==='system-map')return !!state.me?.admin;
  if(view==='board')return may('board.read');
  const limited=!!state.status?.chats_limited;
  return {settings:!!state.me?.admin,'first-run':!!state.me?.admin,start:!!state.me&&!limited,sources:may("sources")&&!limited,evidence:may("export")&&!limited,sealed:may("export")&&!limited,witness:may("settings")&&!limited,
    parameters:may("settings")&&!limited,connection:may("account")&&!limited,accounts:!!state.me?.admin,group:!!state.me?.admin,
    access:!!state.me?.admin,"system-log":!!state.me?.admin,integrations:!!state.me?.admin,
    analysis:!!(state.status?.analysis?.enabled||state.status?.analysis?.media_available)}[view]??true;
}
function applyAccess(){
  const stamp=JSON.stringify([state.workspaceRevision,state.me,state.status?.chats_limited,state.status?.demo,state.status?.analysis]);
  if(stamp===state.permissionsStamp)return;state.permissionsStamp=stamp;
  boardReady.then(()=>{for(const id of ['chat-to-slice','journal-to-slice'])$(id).hidden=!may('board.write');});
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
  panelQueries("[data-export], .report-card, .export-language").forEach(n=>n.hidden=!viewAllowed("evidence"));
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
  const guided=$("connect-details");
  if(guided&&!guided.closest("[hidden]")){guided.open=true;guided.scrollIntoView({block:"start"});return;}
  connectionSettings(true);$("network-details").open=true;$("connection-options").scrollIntoView({block:"start"});
});
$("open-demo").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  state.token=state.demoToken;state.profile="default";await unlock();
}));
function syncLive(){
  if(!state.token||!state.status||state.status.demo||window.TGW_ONLINE_DEMO||(!["observations","chats"].includes(state.view)&&!may('board.read'))){
    window.TgWitnessLive?.stop();return;
  }
  const owner=actionOwner();
  window.TgWitnessLive?.start({key:owner.revision+":"+owner.profile+":"+owner.token,head:state.status.stats.head?.seq,tr,
    api:(path,body,options={})=>{if(!owner.current())throw new StaleView();return api(path,body,{...options,profile:owner.profile,token:owner.token});},
    accessEnded:()=>{if(owner.current())lock();},
    hosts:[viewQuery(state.view,state.view==='chats'?'#chat-live':'.journal .card-heading')].filter(Boolean),
    canRefresh:()=>{
      if(!owner.current()||!['observations','chats'].includes(state.view))return false;
      if(state.drawerSeq!==null||window.getSelection()?.toString()||document.hidden)return false;
      if(state.view==="chats"){const feed=$("chat-feed");return state.chatNextAfter===null&&feed.scrollHeight-feed.scrollTop-feed.clientHeight<80;}
      return state.eventBefore===null&&state.events.length<=200&&window.scrollY<120&&window.TgWitnessJournal?.canRefresh()!==false;
    },
    refresh:async({force=false}={})=>{if(!owner.current())throw new StaleView();await refreshStatus();if(!owner.current())throw new StaleView();if(state.view==="chats"){
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
    const selected=n.dataset.view===(view==="sealed"?"evidence":view==="group"?"accounts":view);
    n.classList.toggle("active",selected);
    if(selected)n.setAttribute("aria-current","page");else n.removeAttribute("aria-current");
  });
  $("view-label").textContent=tr({'system-map':'System map',topology:'Network topology',settings:'Settings','first-run':'First setup',start:"Start here",chats:"Chats",observations:"Journal",sources:"Sources",evidence:"Exports",sealed:"Exports",witness:"Extras",parameters:"Parameters",connection:"Account",accounts:"Accounts",group:"Group",access:"Access","system-log":"System log",integrations:"Integrations",analysis:state.status?.analysis?.enabled?"Ask the archive":"Machine recognition"}[view]);
  show("entry-header",view==="connection");
  if(view==="connection")connectionSettings(false);
  if(state.status){renderSetup();renderWorkflowControls();}
  if(options.history!==false)window.TgWitnessRouter?.record();
  return entered;
}
$("manage-profiles").addEventListener("click",async()=>{
  const revision=state.workspaceRevision;await navigate('accounts');
  if(revision!==state.workspaceRevision||state.view!=='accounts')return;
  $('account-create-details').open=true;$('account-add-label').focus();
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
  const attention=jobs.filter(job=>['failed','partial','paused'].includes(job.phase)||job.phase==='waiting'&&job.active===false).length;
  $('exports-job-summary').textContent=tr('Account exports: {total} · in progress: {active} · ready: {ready} · review: {attention}',
    {total:jobs.length,active,ready:jobs.filter(job=>job.ready).length,attention});
}
function renderWorkflowControls(){
  if(!state.status||!accountState)return;
  const info=accountState(state.status),canExport=!!state.me?.admin&&viewAllowed('evidence');
  if(state.view==='start'){
  show('workflow-link-card',!state.status.demo&&may('export'));
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
function openWorkflowSignIn(){
  const entered=navigate('connection');
  if(state.view==='connection'&&['code-form','password-form','qr-state'].every(id=>$(id).hidden))
    setAuthStep('credentials');
  return entered;
}
async function openAccountWorkflow(){
  if(!state.me?.admin||!viewAllowed('evidence'))return;
  const workflow=state.workflow={profile:state.profile,kind:'account'},revision=state.workspaceRevision;
  const current=()=>state.workflow===workflow&&revision===state.workspaceRevision&&state.me?.admin&&viewAllowed('evidence');
  if(!state.status.demo&&!accountSignedIn()){
    await openWorkflowSignIn();return;
  }
  selectExportTask('account');await navigate('evidence');
  if(current()&&state.view==='evidence'){exportsView?.select('downloads');$('account-export-configure').click();}
}
panelQueries('[data-workflow]').forEach(button=>button.addEventListener('click',()=>busy(button,async()=>{
  if(button.dataset.workflow==='account'){await openAccountWorkflow();return;}
  state.workflow=null;
  if(!viewAllowed('sources')||!viewAllowed('connection')||!may('collect'))return;
  if(!accountSignedIn()&&!state.status.demo){await openWorkflowSignIn();return;}
  await navigate(hasSources(state.status)?'chats':'sources');
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
    const rank={simple:0,standard:1,expert:2}, hiddenLevel=rank[nav.dataset.level]>rank[document.documentElement.dataset.uiLevel];
    if(!query&&hiddenLevel)continue;
    const title=[...nav.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join("").trim();
    const keywords=nav.dataset.view==="witness"?tr("bot Telegram proof GitHub witness"):
      nav.dataset.view==="connection"?tr("proxy MTProxy SOCKS5 HTTP connection route"):"";
    if(!(`${title} ${nav.dataset.view} ${keywords}`).toLocaleLowerCase().includes(query))continue;
    const option=node("div","quick-option");
    option.id="quick-option-"+nav.dataset.view;option.setAttribute("role","option");
    option.dataset.destination=nav.dataset.view;
    option.append(nav.querySelector("svg").cloneNode(true),node("span","quick-label",title));
    if(hiddenLevel)option.append(node('small','',tr('Show hidden setting')));
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
function accountLossText(cause){
  return {account_banned:tr("Telegram banned this account. Observation stopped; the journal is kept."),
    account_frozen:tr("Telegram froze this account and refuses most requests. Observation stopped; the account can appeal through @SpamBot."),
    account_deleted:tr("The Telegram account was deleted. Observation stopped; the journal is kept."),
    session_duplicated:tr("Telegram ended this session because it was used in two places at once. Sign in again with a new session.")}[cause]
    ||tr("Telegram signed this account out. Sign in again to resume observation.");
}
function telegramPauseText(p){
  return p.telegram_pause_method?tr("Telegram paused this account's requests until {time} (method {method}).",{time:fmtFull(p.telegram_pause_until),method:p.telegram_pause_method}):
    tr("Telegram asked to pause requests until {time}.",{time:fmtFull(p.telegram_pause_until)});
}
function collectorLines(name,p){
  const c=p.counts||{};
  if(name==="connection"){
    const paused=p.telegram_pause_until&&new Date(p.telegram_pause_until).getTime()>Date.now();
    if(p.reason==="connected")return [tr("Connected to Telegram.")];
    if(p.reason==="reconnecting")return [tr("Connection lost; reconnecting (attempt {n}).",{n:p.attempts}),
      p.next_reconnect_at&&tr("Next attempt: {time}",{time:fmtFull(p.next_reconnect_at)}),p.error&&tr("Last error: {error}",{error:p.error})];
    if(p.reason==="telegram_pause")return [telegramPauseText(p),tr("Observation waits and resumes on its own.")];
    if(p.reason==="signed_out")return [accountLossText(p.cause)];
    if(p.reason==="collector_error")return [tr("Observation stopped after an error: {error}",{error:p.error?errorName(p.error)||p.error:"?"})];
    if(p.reason==="storage_error")return [tr("Observation stopped: the journal could not be written.")];
    if(p.reason==="resume_failed")return [tr("Observation did not resume after the restart: {error}",{error:p.error?errorName(p.error)||p.error:"?"})];
    if(p.reason==="paused")return [tr("Observation is paused."),paused&&telegramPauseText(p)];
    return [tr("No Telegram account is connected.")];
  }
  if(name==="intake"){
    const facts=[tr("Collector heartbeat: {time}",{time:when(p.last_heartbeat)}),tr("Last event received: {time}",{time:when(p.last_event_at)})];
    if(p.reason==="journal_write_failures")return [p.error,...facts];
    if(p.reason==="live")return [tr("Events arrive. A quiet chat without new messages is not a fault."),...facts];
    if(p.reason==="session_revoked")return [tr("The session was ended from another device or by Telegram."),...facts];
    if(p.reason==="updates_diverted")return [tr("Updates are going to another session: Telegram's update counter grows, but nothing reaches this one. Another client probably uses the same session key."),...facts];
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
    if(p.reason==="access_lost")return [tr("The account was removed from every source or can no longer read them."),counts];
    if(p.reason==="some_access_lost")return [tr("The account was removed from some sources or can no longer read them; nothing arrives from those. The others continue."),counts];
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
const healthReady=import("./components/health.js?v=layout1").then(({createHealthBar})=>{
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
let modesUI=null;
const modeSession=()=>state.workspaceRevision+":"+state.profile;
const modesReady=import("./components/modes.js?v=1").then(({createModes})=>{
  modesUI=createModes({node,tr,json,may,status:()=>state.status,query:panelQueries,go:goPlace,toast});
  if(state.status&&!$("workspace").hidden)modesUI.sync(modeSession());
  return modesUI;
});
modesReady.catch(error=>toast(error.message,true));
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
    c.last_error ? tr("Collector reported {error}. Review coverage events before relying on completeness.",{error:errorName(c.last_error)||c.last_error}) : "";
  renderSetup();
  renderWorkflowControls();
  if($("credentials-form").isConnected)renderAccountIdentity(s);
  modesUI?.sync(modeSession());
  viewHost?.updateStatus(s);
}
function renderAccountIdentity(s){
  const account=s.collector.account;
  const identity=account ? (account.username ? "@"+account.username+" · " : "") + "ID "+account.id : "";
  if($("account-summary").isConnected){
    show("account-summary",!!account);
    $("account-summary").textContent=account ? tr(accountState(s).needsSignIn?'Sign in again for account: {who}':"Connected account: {who}",{who:identity}) : "";
  }
  show("authorized-account",!!account);$("authorized-account").textContent=identity;
  const avatarKey=account?state.profile+":"+account.id:"";
  if(state.accountAvatar!==avatarKey){
    state.accountAvatar=avatarKey;
    const fresh=account?avatarNode(account.id,account.username||"Account","xl"):node("span","avatar xl");
    fresh.id="authorized-avatar";fresh.hidden=!account;$("authorized-avatar").replaceWith(fresh);
    show("authorized-mark",!account);
  }
  renderApiState();
  window.TgWitnessAccountImport?.renderAccount();
}
function renderOverviewEmpty(s){
  const box=$("overview-empty"),counts=s.stats.counts,c=s.collector;
  const recorded=["message.new","message.snapshot","message.edited","message.deleted"].some(kind=>counts[kind]);
  box.hidden=recorded||s.demo;if(box.hidden)return;
  const sources=hasSources(s),action=!c.has_session?["Connect account →","connection"]:!sources?["Choose sources →","sources"]:c.running?null:["Start observation",null];
  const text=!c.has_session?"Nothing recorded yet. Connect a Telegram account to start the journal.":!sources?"Nothing recorded yet. Choose the chats to observe.":
    c.running?"Observation is on. New messages, edits and deletion notices appear here when Telegram delivers them.":"Nothing recorded yet. Start observation to save new activity.";
  box.replaceChildren(node("p","",tr(text)));
  if(action){const b=node("button","secondary small",tr(action[0]));b.type="button";
    b.addEventListener("click",()=>action[1]?navigate(action[1]):$("collector-toggle").click());box.append(b);}
}
function renderViewStatus(view){
  const s=state.status;if(!s||viewHost?.active!==view)return;
  const c=s.collector,counts=s.stats.counts;
  if(view==='start'){renderWorkflowControls();renderSetupStart();}
  else if(view==='observations'){
    $("stat-messages").textContent=((counts["message.new"]||0)+(counts["message.snapshot"]||0)).toLocaleString();
    $("stat-edits").textContent=(counts["message.edited"]||0).toLocaleString();
    $("stat-deletes").textContent=(counts["message.deleted"]||0).toLocaleString();
    $("stat-sources").textContent=s.targets.filter(x=>x.enabled).length;
    $("sources-footnote").textContent=tr(s.demo ? "Synthetic sources" : c.running ? "Observation enabled" : "Observation paused");
    renderOverviewEmpty(s);
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
  else{$("collector-toggle").click();if(modesUI?.mode()==="easy")navigate("chats");}
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
  workspaceSafety?.acceptStatus(result);
  state.status=result;applyAccess();renderStatus();workspaceSafety?.sync();
  settingsHub?.status();
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
    info.append(node("h3","",profile.label),node("p","",profile.error_type==="DeletionPending"?tr("Deletion incomplete"):profile.error_type?tr("Unavailable: {error}",{error:errorName(profile.error_type)||profile.error_type}):
      (accountState(profile).needsSignIn?tr("Sign-in required"):termText(profile.collector?.phase||"offline"))+" · "+trn("{n} journal event","{n} journal events",profile.stats?.total||0)));
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
  renderAccounts();window.TgWitnessAccountImport?.renderAccount();
  if(state.view==='group')groupView?.status();
}
function accountPhaseLabel(p){
  if(p.error_type==="DeletionPending")return tr("Deletion incomplete");
  if(p.error_type)return tr("Unavailable")+" · "+(errorName(p.error_type)||p.error_type);
  return tr(accountState(p).label);
}
function accountIdentity(p){
  const a=p.collector&&p.collector.account;
  if(!a)return tr(p.collector&&p.collector.has_session?"Signed in":"No account connected");
  return (a.username?"@"+a.username+" · ":"")+"ID "+a.id;
}
let accountsView=null;
import("./views/accounts.js?v=layout1").then(({createAccounts})=>{
  accountsView=createAccounts({root:$("view-accounts"),tr,getState:()=>state,getSession:()=>state.workspaceRevision+":"+state.profile,
    json,loadProfiles,refreshStatus,toast,switchProfile,navigate,diagnose:openDiagnostics});
  window.TgWitnessAccounts=accountsView;
  if(state.view==='accounts')renderAccounts();
  return accountsView;
}).catch(error=>toast(error.message,true));
let groupView=null;
const groupViewReady=import("./views/group.js?v=2").then(({createGroupView})=>{
  groupView=createGroupView({root:$("view-group"),json,tr,trn,node,toast,getState:()=>state,avatarNode,stateBadge,
    accountState:p=>accountState(p),accountPhaseLabel,healthPartNames,collectorLines,needsLook,fmtTime,fmtDuration,may,
    switchProfile,navigate,loadProfiles,diagnose:openDiagnostics,openChat:openChatIn,exportTogether,
    exportGroup:(id,label,owner)=>download('profile-groups/'+encodeURIComponent(id)+'/export','tgwitness-group-'+label.replace(/[^A-Za-z0-9._-]+/g,'-')+'.zip',true,true,undefined,undefined,{owner}),
    openConnection:async preset=>{await navigate('connection');await connectionViewReady;connectionView.preset(preset);},
    openGroupSettings:async id=>{await navigate('settings');if(state.view==='settings'){await settingsHubReady;await settingsHub.openGroup(id);}}});
  return groupView;
}).catch(error=>toast(error.message,true));
function openGroup(id){state.groupId=id;return navigate('group');}
window.TgWitnessOpenGroup=openGroup;
async function openChatIn(profileId,chatId){
  if(state.profile!==profileId&&await switchProfile(profileId)===false)return false;
  if(state.profile!==profileId||!state.token)return false;
  await navigate('chats',{load:false,history:false});await refreshChats(false,chatId);
  return await openChat(chatId)!==false;
}
let exportPreselect=null;
async function exportTogether(profileId,chatId,members){
  if(!await openChatIn(profileId,chatId))return;
  exportPreselect=new Set(members);
  try{await openExportDialog();}finally{exportPreselect=null;}
}
function renderAccounts(){
  if(state.view!=='accounts')return;
  const grid=$("accounts-list"),s=state.status;if(!grid||!s)return;
  window.TgWitnessFleet?.beforeRender?.();
  const cards=new Map(viewQueries('accounts','.account-card[data-profile]').map(card=>[card.dataset.profile,card]));
  const list=state.profiles||[];
  $("accounts-limit").textContent=trn("{n} workspace. Add as many as you need — each uses its own Telegram account.",
    "{n} workspaces. Add as many as you need — each uses its own Telegram account.",list.length);
  $("account-add-form").querySelector("button").disabled=s.demo;
  const exits=new Map();
  for(const value of list){const net=value.collector?.network,ip=net?.check?.exit_ip;if(ip&&net.managed!=="warp")exits.set(ip,(exits.get(ip)||0)+1);}
  for(const value of list){
    const existing=cards.get(value.id),p=existing?Object.assign(existing.profileData,value):value;
    const c=p.collector,current=p.id===state.profile,down=!!p.error_type||!c;
    const card=node("div","card padded account-card"+(current?" current":""));card.dataset.profile=p.id;card.profileData=p;
    const head=node("div","account-head"),who=node("div","account-who"),account=c&&c.account;
    const title=node("div");title.append(node("h2","",p.label));
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
      const restricted=c.account_restriction&&(!c.account_restriction.until||c.account_restriction.until*1000>Date.now())?c.account_restriction:null;
      pair(tr("Route"),[routeText(c.network),exitText(c.network?.check)].filter(Boolean).join(" · ")||"—","route");
      const sharing=exits.get(c.network?.check?.exit_ip)||0;
      if(sharing>1)meta.lastElementChild.lastElementChild.append(node("span","route-shared",tr("Same exit address as other accounts: {n}",{n:sharing-1})));
      if(restricted)pair(tr("Telegram restriction"),restrictionText(restricted.kind),"restriction");
      pair(tr("Sources"),(p.sources_enabled||0)+(p.sources_total?" / "+p.sources_total:""),"sources");
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
        const owner=actionOwner(),running=!!p.collector?.running;
        if(running&&!(await (await collectionReady).confirmPause(p.label)))return;
        if(!owner.current())return;
        await json("collector/"+(running?"stop":"start"),{},{profile:p.id,token:owner.token});
        toast(tr(running?"Paused collection for {name}.":"Started collection for {name}.",{name:p.label}));
        await loadProfiles();if(p.id===state.profile)await refreshStatus();
      }));
      actions.append(toggle);
    }
    const rename=node("button","quiet",tr("Rename"));rename.dataset.action='rename';rename.disabled=state.status.demo;
    rename.addEventListener("click",()=>busy(rename,async()=>{
      const label=((await askText(tr("New name for this workspace:"),{title:tr("Rename"),value:p.label,maxLength:80}))||"").trim();
      if(!label||label===p.label)return;
      await api("profiles/"+encodeURIComponent(p.id),{label},{root:true,method:"PATCH"});
      toast(tr("Renamed workspace."));await loadProfiles();
    }));
    actions.append(rename);
    if(p.id!=="default"){
      const del=node("button","danger",tr("Delete"));del.dataset.action='delete';del.disabled=state.status.demo||!!p.deletion_blocked;
      if(p.deletion_blocked)del.title=tr(p.deletion_blocked);
      del.addEventListener("click",()=>busy(del,async()=>{
        if(!(await askTyped(tr("Delete \"{name}\" permanently? This stops its collector and erases its journal, sources, signing key and the copy of its session kept here. The session stays active in Telegram: deleting does not sign it out. This cannot be undone.",{name:p.label}),p.label,{title:tr("Delete"),confirmText:tr("Delete")})))return;
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
      }).then(renderAccounts));
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
      if(button.title)old.title=button.title;else old.removeAttribute('title');
      if(!old.hasAttribute('aria-busy'))old.disabled=button.disabled;return old;}));
  }
  for(const [id,card] of cards)if(!list.some(profile=>profile.id===id))card.remove();
  window.TgWitnessFleet?.decorate();accountsView?.updateStatus();
}
async function switchProfile(id,options={}){
  if(!state.profiles.some(profile=>profile.id===id))await loadProfiles();
  if(!state.profiles.some(profile=>profile.id===id&&!profile.error_type))throw new Error(tr('Unknown workspace.'));
  if(id!==state.profile&&(state.accountExportDirty||state.accountDisclosureDirty)&&
      !options.discardConfirmed&&!(await askConfirm(tr("Discard unsaved settings in this workspace and switch accounts?")))){
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
  window.TgWitnessServices?.clear();
  window.TgWitnessIndependentCapture?.clear();
  quickDialog.close();window.TgWitnessDialogs?.closeAll();modesUI?.reset();
  const revision=++state.workspaceRevision;
  settingsHub?.reset();
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
  state.status=null;$("profile-select").value=id;
  if(options.history!==false)window.TgWitnessRouter?.record({workspace:id,chatId:null,seq:null});
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
  await bootstrapSettings({openFirstRun:options.history!==false});
  if(revision!==state.workspaceRevision)return;
  await navigate(state.view,{history:false});
  await loadNotifications().catch(()=>{});
  if(revision!==state.workspaceRevision)return;
  setAuthStep(accountSignedIn()?"authorized":"credentials");
  syncLive();
  workspaceSafety?.sync();
  if(options.history!==false)window.TgWitnessRouter?.record({}, {replace:true});
  toast(tr("Switched workspace. Other collectors keep their current state."));
  }catch(error){if(revision===state.workspaceRevision)unlockFailed(error);throw error;}
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
function accessName(p) {
  return p.access_id==="admin"||p.label==="Main administrator"?tr("Main administrator"):p.label||state.accessNames?.[p.access_id]||p.access_id||"";
}
function excerpt(e) {
  const p=e.payload;
  if (p.ephemeral_media) return [excerpt({...e,payload:{...p,ephemeral_media:null}}),
    ephemeralMediaText(p.ephemeral_media)].filter(Boolean).join(" · ");
  if (p.text) return p.text;
  if (e.kind==="message.deleted") return p.auto_delete?.expected?tr("Expected: the message's auto-delete timer expired when the deletion was seen."):tr("Earlier captured versions remain available. The chat's admin log, read by an admin account in history or chat export, names the deleting administrator.");
  if (e.kind==="message.missing_on_recheck") return p.auto_delete?.expected?tr("Expected: the message's auto-delete timer had expired before this check."):tr("Telegram no longer returns this message; no deletion notice was received.");
  if (e.kind==="history.cleared") return tr("Messages deleted together")+" · "+String(p.count??"");
  if (e.kind==="replica.completed") return p.error?tr("Stopped: {error}",{error:errorName(p.error)||p.error}):tr("{n} encrypted object(s), {size}",{n:p.objects,size:humanSize(p.bytes)});
  if (e.kind==="alerts.changed") return p.enabled?tr("On · {n} destination(s)",{n:p.destinations}):tr("Off");
  if (e.kind==="replica.changed") return p.enabled?tr("On · {bucket} · every {n} min",{bucket:p.bucket,n:p.interval_minutes}):tr("Off");
  if (e.kind==="anchor.completed") return tr("{ok} of {total} services answered for the checkpoint of {n} records",{ok:p.results.filter(r=>r.ok).length,total:p.results.length,n:p.checkpoint.event_count});
  if (e.kind==="source.checked") return (p.matches?tr("Matches"):tr("Differs"))+" · "+p.repository.replace("https://github.com/","")+" @ "+p.commit.slice(0,12);
  if (e.kind==="evidence.changed") return p.enabled?tr("On · every {n} min · {services} services",{n:p.interval_minutes,services:p.tsa_urls.length+p.ots_calendars.length}):tr("Off");
  if (e.kind==="workspace.mode_changed"){
    const name=id=>tr({easy:"Easy",signed:"Signed",witnessed:"Witnessed",court:"Case preparation",github:"GitHub-verified",mossad:"Mossad"}[id]||String(id));
    return (p.from?name(p.from)+" → ":"")+name(p.to)+({"existing installation":" · "+tr("set for an existing installation"),later:" · "+tr("kept until a choice is made")}[p.reason]||"");
  }
  if (e.kind==="handover.exported") return p.purpose||"";
  if (e.kind==="storage.low") return tr("Photo & file downloads paused at {size} free; queued files are kept.",{size:humanSize(p.free_bytes)});
  if (e.kind==="storage.ok") return tr("Photo & file downloads resumed · {size} free",{size:humanSize(p.free_bytes)});
  if (e.kind==="recheck.completed") return tr("{chats} chat(s) · {recovered} recovered · {edited} edited · {missing} not found",{chats:p.chats.length,recovered:p.recovered,edited:p.edited,missing:p.missing});
  if (e.kind==="reaction.snapshot") return p.counts ? Object.entries(p.counts).map(([k,v])=>k+" "+v).join("  ·  ") : tr("Reaction snapshot received · actor list may be incomplete");
  const failure=p.error_type ? " · "+(errorName(p.error_type)||p.error_type) : "";
  switch (e.kind) {
    case "actor.profile_changed": return Object.entries(p.changes||{}).map(([k,c])=>(k==="display_name"?tr("Name"):k==="username"?tr("Username"):k)+": "
      +[c.before,c.after].map(v=>v==null||v===""?"—":k==="username"?"@"+v:v).join(" → ")).join(" · ");
    case "actor.avatar_saved": return p.previous_photo_id===undefined?"":p.previous_photo_id===null?tr("Added a profile photo"):tr("Replaced the previous profile photo");
    case "interaction.preview": return [p.title,p.link].filter(Boolean).join(" · ");
    case "secret_chat.message": return (p.direction==="out"?tr("Sent"):tr("Received"))+" · "+(p.text||(p.media?tr("Attachment"):""))+(p.ttl?" · "+tr("timer {n} s",{n:p.ttl}):"");
    case "secret_chat.requested": return (p.direction==="out"?tr("Started by this account"):tr("Started by the other side"))+" · "+tr("user ID {id}",{id:p.peer_user_id});
    case "secret_chat.ready": return tr("Key picture {hex}",{hex:(p.key_visualization||"").slice(0,16)+"…"});
    case "secret_chat.action": return secretActionText(p);
    case "secret_chat.closed": return p.history_deleted_by_peer?tr("The other side deleted the chat; the journal keeps every record."):p.reason||"";
    case "secret_chat.file": return humanSize(p.size)+" · SHA-256 "+String(p.media_sha256||"").slice(0,12)+"…";
    case "secret_chat.file_deferred": return p.reason||"";
    case "interaction.requested": return [p.request?.action,p.button?.text,p.request?.text].filter(Boolean).join(" · ");
    case "interaction.result": return [p.status,p.answer?.message,p.answer?.url,errorName(p.error_type)||p.error_type].filter(Boolean).join(" · ");
    case "account.authorized": return tr("Telegram account ID {id}",{id:p.account_id});
    case "account.signed_out": return tr("Telegram account ID {id}",{id:p.account_id})+(p.telegram_session_ended?"":" · "+tr("Telegram did not confirm the end of the session"))+failure;
    case "media.skipped": {
      const type=/^attachment type not collected by policy: (\w+)$/.exec(p.reason||"")?.[1];
      if(type)return tr("Not collected by the attachment settings: {type}",{type:MEDIA_TYPE_LABELS[type]?tr(MEDIA_TYPE_LABELS[type]):termText(type)});
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
    case "capture.changed": return p.download_media ? tr("Attachments on · {list}",{list:mediaLimitText(p)}) : tr("Attachment downloads off");
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
    case "network.connection_checked": return p.telegram_connected?[tr("Telegram connected"),p.exit_ip,countryName(p.country),p.warp?"WARP: "+p.warp:"",
      p.latency_ms!=null?p.latency_ms+" ms":""].filter(Boolean).join(" · "):tr("Not connected")+failure;
    case "connection.opened": case "connection.closed": return [routeText(p.route),p.dc_id?"DC "+p.dc_id:"",
      p.role==="current"?"":tr({candidate:"sign-in connection",other:"helper connection"}[p.role]||p.role)].filter(Boolean).join(" · ");
    case "account.sessions": return tr("Other sessions: {n}",{n:(p.others||[]).length})+
      ((p.added||[]).length?" · "+tr("new: {n}",{n:p.added.length}):"")+((p.removed||[]).length?" · "+tr("ended: {n}",{n:p.removed.length}):"");
    case "account.session_ended": return [p.device_model,[p.app_name,p.app_version].filter(Boolean).join(" "),p.country].filter(Boolean).join(" · ");
    case "account.restricted": case "account.restriction_expired": return restrictionText(p.kind);
    case "account.read_only": return tr(p.enabled?"On":"Off");
    case "profile.created": return p.label||workspaceName(p.id);
    case "profile.unavailable": return workspaceName(p.profile_id)+failure;
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
    case "access.granted": case "access.changed": return accessName(p)+" · "+(p.permissions||[]).map(x=>permissionLabels[x]?.[0]||x).join(", ");
    case "access.revoked": return accessName(p);
    case "access.session_started": return accessName(p)+(p.address?" · "+p.address:"");
    case "access.session_ended": return accessName(p)+" · "+(sessionEndReasons[p.reason]||p.reason||"");
    case "witness.seen": return (p.label||"")+" · "+String(p.witness_fingerprint||"").slice(0,16);
  }
  if (p.reason) return p.reason;
  if (p.service_action) return p.service_action;
  if (p.action) return p.action._ || tr("Telegram service action");
  if (p.coverage) return tr(p.coverage);
  if (p.meaning) return p.meaning;
  return tr("Open the source record for observation details");
}
function safeExcerpt(e){
  try{return excerpt(e);}
  catch(error){console.error("Journal record #"+e.seq+" could not be summarised",error);return tr("Open the source record for observation details");}
}
let previouslyFocused;
function eventRow(e) {
    const label=labels[e.kind] || [e.kind,"activity","system"];
    const row=node("tr","event-row"); row.tabIndex=0; row.setAttribute("role","button"); row.setAttribute("aria-label",tr("Open {label} event {seq}",{label:label[0],seq:e.seq}));
    const cell=node("td"), summary=node("div","event-summary"), text=node("div");
    const title=node("div","event-title",label[0]); title.append(node("span","",tr("Record #{n}",{n:e.seq})));
    const mobileMeta=node("div","event-mobile-meta",sourceTitle(e.chat_id)+" · ");
    mobileMeta.append(timeNode(e.observed_at));text.append(title,node("div","event-excerpt",window.TgWitnessPrivacy.preview(safeExcerpt(e))),mobileMeta);
    if(e.match?.machine_recognition){
      const found=node("div","event-match",tr(e.match.source==="transcription"?"Matched in the transcript (machine recognition):":"Matched in recognized image text (machine recognition):"));
      found.append(node("q","",window.TgWitnessPrivacy.preview(e.match.excerpt||"")));text.append(found);
    }
    const mark=node("span","event-icon "+label[2]); mark.append(icon(label[1]));
    summary.append(mark,text); cell.append(summary);
    const source=node("td"); source.append(node("span","source-title",sourceTitle(e.chat_id)),node("span","source-id",e.chat_id || tr("system")));
    const time=node("td");time.append(timeNode(e.observed_at,"event-time"));
    const open=node("td","event-open"); open.append(icon("chevron"));
    row.append(cell,source,time,open);
    row.addEventListener("click",()=>openDetail(e));
    row.addEventListener("keydown",event=>{ if(event.target===row&&(event.key==="Enter"||event.key===" ")){event.preventDefault();openDetail(e);} });
    row.dataset.seq=String(e.seq);
    boardView?.attach(row,e);
    return row;
}
function renderEvents() {
  if(state.view!=='observations')return;
  try{window.TgWitnessJournal.renderRows(state.events,eventRow);}
  finally{window.TgWitnessJournal.syncPage();}
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
  if(state.search&&state.searchMode==="relevance"&&!state.boardSlice){await refreshRanked(++state.request);return;}
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
  if(state.boardSlice){params.set('slice_id',state.boardSlice);params.set('added_since',String(!!state.boardAdded));}
  if(after!==null)params.set("after",after);else if(before!==null)params.set("before",before);
  const result=await json("events?"+params,undefined,viewOptions('observations'));
  if(request!==state.request)return;
  state.events=result.events.slice(0,200);state.cursor=result.next_before??null;state.eventAfter=result.next_after??null;
  state.eventMatched=result.count_exact?result.matched:null;
  state.eventBefore=after!==null?(state.eventAfter!==null&&result.events.length?result.events[0].seq+1:null):before;
  renderEvents();
  if(direction)window.TgWitnessRouter?.record({seq:null,before:state.eventBefore});
}
async function refreshRanked(request) {
  const params=new URLSearchParams({q:state.search,limit:"200",source:state.searchSource||"messages"});
  if(state.source)params.set("chat_id",state.source);
  if(state.eventSince)params.set("since",state.eventSince);
  if(state.eventUntil)params.set("until",state.eventUntil);
  const result=await json("search?"+params,undefined,viewOptions('observations'));
  if(request!==state.request)return;
  const counts=Object.values(result.matched||{});
  state.events=result.events;state.cursor=state.eventAfter=state.eventBefore=null;
  state.eventMatched=counts.length&&counts.every(Number.isFinite)?counts.reduce((a,b)=>a+b,0):null;
  state.searchIndex=result.index;
  renderEvents();
}
const journalReady=import('./components/journal.js?v=layout1').then(({createJournal})=>{
  window.TgWitnessJournal=createJournal({get:$,state,node,icon,tr,invalidate:()=>{state.request++;},error:message=>toast(message,true),
    request:(path,body)=>json(path,body),admin:()=>!!state.me?.admin,
    changed:async()=>{state.boardSlice=null;state.boardAdded=false;$('board-slice-context')?.remove();state.cursor=state.eventBefore=state.eventAfter=state.eventMatched=null;closeDetail({history:false});window.TgWitnessRouter?.record({seq:null});await refreshEvents();},
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
  const profile=state.profile,revision=state.workspaceRevision,action=state.status.collector.running?'stop':'start';
  if(action==='stop'&&!await (await collectionReady).confirmPause())return;
  if(profile!==state.profile||revision!==state.workspaceRevision)return;
  await json("collector/"+action,{},{profile});
  await refreshStatus();await refreshEvents();
}));
function detailBlock(label,text,cls="") {
  const n=node("div","detail-block "+cls); n.append(node("small","",label),window.TgWitnessPrivacy.render(text||tr("(No text in this version)"),{className:"message-text",tr})); return n;
}
function ephemeralMediaText(facts) {
  const title=facts.mode==="view_once"?tr("View-once media"):tr("Self-destructing media: {n} s",{n:facts.ttl_seconds});
  const outcomes={saved:"File preserved",unavailable:"Attachment unavailable when observed",not_saved:"File not preserved",
    retry:"Preservation pending",hashed:"File hashes; content not downloaded"};
  const detail=outcomes[facts.outcome]||(facts.availability==="unavailable_at_observation"?outcomes.unavailable:null);
  const opened=facts.observer_opened===false?tr("Not opened by the observing account"):facts.observer_opened===true?tr("Opened by the observing account"):null;
  return [title,opened,detail?tr(detail):null,tr("This attachment was saved when Telegram delivered it to this account."),
    facts.outcome&&facts.outcome!=="saved"?tr("Self-destructing media may disappear before another attempt."):null].filter(Boolean).join(" · ");
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
    [tr("Message sender / supplied actor"),sender ?? tr("No data")],
    [tr("Action attribution"),tr(e.kind==="message.edited" ? "Message author; in channels also an administrator with edit rights" : e.kind==="message.deleted" ? "The chat's admin log, when read by an admin account" : "See raw record and visibility notes")],
    [tr("Technical sequence (seq)"),e.seq],
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
  content.append(node("p","detail-caption",window.TgWitnessPrivacy.preview(excerpt(e))));
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
        if(previous){const presentation=value=>JSON.parse(window.TgWitnessPrivacy.recordPreview(value));
          versions.append(window.TgWitnessReview.compare(presentation(previous.payload),presentation(e.payload),tr));}
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
let sourcesView=null;
const sourcesReady=import("./views/sources.js?v=2").then(({createSources})=>{
  sourcesView=createSources({root:$("view-sources"),tr,getState:()=>state,
    getSession:()=>state.workspaceRevision+":"+state.profile,may,json,refreshStatus,toast,termText,scopeName,icon,loadScope,formatTime,
    setDialogs:result=>{state.dialogs=result.dialogs;if(state.scope)state.scope.folders=result.folders||[];},
    renderScope,focusObservation:()=>$("collector-toggle").focus({preventScroll:true}),
    confirm:(message,options)=>askConfirm(message,options),
    scopeExclusions:(ids,excluded)=>{if(state.scopeDirty)state.scopeExclude=excluded?
      [...new Set([...state.scopeExclude,...ids])]:state.scopeExclude.filter(id=>!ids.includes(id));},
    setDirty:dirty=>{state.monitoringDirty=dirty.monitoring;state.captureDirty=dirty.capture;state.recheckDirty=dirty.recheck;},
    saved:result=>{for(const name of ["monitoring","capture","recheck"])state.status[name]=result[name];},
    onTab:name=>{void showSecretChats(name==="secret");}});
  if(state.view==="sources"&&!$("workspace").hidden)sourcesView.enter();
  return sourcesView;
}).catch(error=>{toast(error.message,true);throw error;});
let secretChatsView=null,secretChatsLoading=null;
window.addEventListener("tgwitness:lock",()=>secretChatsView?.reset());
async function showSecretChats(visible){
  if(!visible){secretChatsView?.leave();return;}
  if(state.status?.demo)return;
  secretChatsLoading??=import("./views/secret-chats.js?v=2").then(({createSecretChats})=>secretChatsView=createSecretChats({
    root:$("view-sources"),tr,trn,json,toast,busy,node,formatTime,download,confirm:(message,options)=>askConfirm(message,options),
    getSession:()=>state.workspaceRevision+":"+state.profile,may,humanSize,actionText:secretActionText}));
  try{await (await secretChatsLoading).enter();}catch(error){if(!(error instanceof StaleView))toast(error.message,true);}
}
function renderTargets() { sourcesView?.renderTargets(); }
const MEDIA_ORDER=["photo","video","document","voice","audio","video_note","animation","sticker"];
function mediaLimitText(c,short=false){
  const types=c?.types||{};
  if(!Object.keys(types).length)return tr("up to {n} MB per file",{n:c?.max_media_mb});
  const on=MEDIA_ORDER.filter(t=>types[t]?.enabled);
  if(!on.length)return tr("no attachment types");
  const part=t=>tr("{type} {n} MB",{type:tr(MEDIA_TYPE_LABELS[t]),n:types[t].max_mb});
  if(!short)return on.map(part).join(", ");
  return part(on[0])+(on.length>1?" · "+tr("+{n} more",{n:on.length-1}):"");
}
function renderHistory(){
  const s=state.status,h=s?.history||{phase:"none"},phase=h.phase;
  const active=phase==="running",paused=phase==="paused",exists=phase!=="none";
  $("history-options").disabled=active||paused;
  if((active||paused)&&h.options){
    $("history-transport").value=h.options.transport;
    $("history-workers").value=String(h.options.media_workers);
    $("history-admin").checked=h.options.admin_log;
    $("history-compare").checked=h.options.compare_saved;
  }
  show("history-card",may("sources")&&!s?.chats_limited);
  show("history-start",!active&&!paused);show("history-pause",active);
  show("history-resume",paused);show("history-cancel",active||paused);
  show("history-report",exists&&may("export"));
  $("history-start").disabled=!!s?.demo||!s?.collector.has_session||!s?.collector.available_for_export||!s?.targets.some(x=>x.enabled);
  $("history-resume").disabled=!!s?.demo||!s?.collector.has_session||!s?.collector.available_for_export;
  const busyAccount=!s?.demo&&!!s?.collector.has_session&&!s?.collector.available_for_export&&!active;
  show("history-availability",busyAccount);
  $("history-availability").textContent=busyAccount?tr("This account is busy. Pause observation or its current task before loading history."):"";
  const labels={running:tr("Loading history"),paused:tr("History paused"),complete:tr("History reading finished"),
    incomplete:tr("History finished with gaps"),cancelled:tr("History run ended")};
  const counts=h.sources_by_phase||{},finished=(counts.complete||0)+(counts.failed||0)+(counts.skipped||0);
  $("history-progress").textContent=exists?(labels[phase]||phase)+" · "+tr("{messages} messages · {done} of {total} sources",{
    messages:h.captured,done:finished,total:h.sources_total})+(h.reason?" · "+(errorName(h.reason)||tr(h.reason)):""):
    tr("{n} enabled sources. History requires an idle account; pause observation first.",{n:s?.targets.filter(x=>x.enabled).length||0});
  $("history-media").textContent=exists?tr("Attachments: {done} saved, {pending} pending, {failed} failed. Unavailable messages: {missing}.",{
    done:h.media?.done||0,pending:h.media_pending||0,failed:h.media?.failed||0,missing:h.unavailable||0}):"";
  $("history-wait").textContent=h.wait_until>Date.now()/1000?
    tr("Telegram wait until {time}",{time:new Date(h.wait_until*1000).toLocaleString()}):
    exists&&h.pacing?.delay_seconds?tr("Account request spacing: {seconds} s",{seconds:Number(h.pacing.delay_seconds).toFixed(1)}):"";
  const list=$("history-sources");list.replaceChildren();
  const phases={queued:tr("Queued"),reading:tr("Reading history"),complete:tr("History reading finished"),
    failed:tr("Failed"),skipped:tr("Skipped")};
  for(const source of h.sources||[]){
    const admin=["before","after"].map(stage=>{
      const p=source.metadata?.["admin_"+stage];
      const status={reading:tr("Reading"),complete:tr("Complete"),unavailable:tr("Unavailable"),not_applicable:tr("Not applicable")};
      return p?tr("Recent Actions ({stage}): {status} · {count}",{
        stage:stage==="before"?tr("Before history"):tr("After history"),status:status[p.status]||p.status,count:p.observed})+
        (p.error?" · "+(errorName(p.error)||p.error):""):"";
    }).filter(Boolean).join(" · ");
    list.append(node("li","",source.title+" · "+(phases[source.phase]||source.phase)+" · "+source.captured+
      (source.error?" · "+(errorName(source.error)||tr(source.error)):"")+(admin?" · "+admin:"")));
  }
  if(h.sources_total>50)list.append(node("li","hint",tr("The signed report lists every source.")));
}
for(const action of ["start","pause","resume","cancel"]){
  $("history-"+action).addEventListener("click",e=>busy(e.currentTarget,async()=>{
    const options=action==="start"?{transport:$("history-transport").value,
      media_workers:Number($("history-workers").value),admin_log:$("history-admin").checked,
      compare_saved:$("history-compare").checked}:{};
    await json("history/"+action,options);await refreshStatus();await refreshEvents();
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
  $("snapshot-form").querySelector("button").disabled=s.demo||!may("sources")||!s.collector.has_session||!s.collector.available_for_export||!s.targets.some(t=>t.enabled);
  renderRecheck();syncExport(s);renderHandoverChats();
}
const handoverChats=()=>[...$("handover-chats").querySelectorAll("input:checked")].map(input=>Number(input.value));
function renderHandoverChats(){
  const box=$("handover-chats"),chosen=new Set(handoverChats()),targets=state.status?.targets||[];
  show("handover-card",may("export"));
  box.replaceChildren(...targets.map(target=>{
    const label=node("label","check-label"),input=node("input");
    input.type="checkbox";input.value=String(target.chat_id);input.checked=chosen.has(target.chat_id);
    label.append(input,document.createTextNode(" "+(target.title||String(target.chat_id))));return label;
  }));
  if(!targets.length)box.append(node("p","hint",tr("No sources yet: choose chats under Sources first.")));
}
$("handover-load-people").addEventListener("click",event=>busy(event.currentTarget,async()=>{
  const chats=handoverChats();
  if(!chats.length)throw new Error(tr("Choose at least one chat."));
  const chosen=new Set([...$("handover-people").querySelectorAll("input:checked")].map(input=>Number(input.value)));
  const people=new Map();
  for(const chat of chats){
    const result=await json("chats/"+encodeURIComponent(chat)+"/authors");
    for(const author of result.authors||[]){
      if(author.id===null||author.id===undefined)continue;
      const known=people.get(author.id)||{...author,messages:0};known.messages+=author.messages;people.set(author.id,known);
    }
  }
  const box=$("handover-people");
  box.replaceChildren(...[...people.values()].sort((a,b)=>b.messages-a.messages).map(person=>{
    const label=node("label","check-label"),input=node("input");
    input.type="checkbox";input.value=String(person.id);input.checked=chosen.has(person.id);
    label.append(input,document.createTextNode(" "+[person.name,person.username?"@"+person.username:"","id "+person.id]
      .filter(Boolean).join(" · ")+" · "+trn("{n} message","{n} messages",person.messages)));return label;
  }));
  if(!people.size)box.append(node("p","hint",tr("No saved messages in the chosen chats.")));
}));
$("handover-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const chats=handoverChats(),purpose=$("handover-purpose").value.trim();
  if(purpose.length<3){$("handover-purpose").focus();throw new Error(tr("State the purpose of the handover."));}
  if(!chats.length)throw new Error(tr("Choose at least one chat."));
  const choice=name=>viewQuery("evidence",'input[name="'+name+'"]:checked')?.value;
  const moment=id=>$(id).value?$(id).value+":00Z":null;
  const body={purpose,chats,subjects:[...$("handover-people").querySelectorAll("input:checked")].map(input=>Number(input.value)),
    others:choice("handover-others"),text:choice("handover-text"),attachments:choice("handover-files"),
    avatars:$("handover-avatars").checked,mask_contacts:$("handover-contacts").checked,
    since:moment("handover-since"),until:moment("handover-until"),case_board:$("handover-board").value,board_pseudonyms:$("handover-board-aliases").checked};
  const password=$("export-password").value,encrypt=$("export-encrypt-on").checked;
  if(encrypt&&password.length<12){$("export-password").focus();throw new Error(tr("Enter a password of at least 12 characters, or untick encryption."));}
  const encryption=$("export-encryption").value;
  if(encrypt){body.password=password;body.encryption=encryption;}
  if(exportLanguage())body.language=exportLanguage();
  const progress=(await exportsReady).begin({encrypted:encrypt,encryption});
  try{
    const saved=await download("handover",encrypt?"tgwitness-handover-encrypted."+encryption:"tgwitness-handover.zip",true,false,body,progress);
    if(saved)toast(tr("Handover extract saved. Its purpose and rules are recorded in the journal."));
  }catch(error){progress({phase:"failed",error:error.message});throw error;}
});});
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
  const prog=$("chat-export-progress");
  const running=!!x&&x.phase==="running",done=!!x&&x.phase==="done"&&x.ready;
  show("chat-export-cancel",running);show("chat-export-download",done);
  const percent=running&&x.total?Math.min(99,Math.floor((x.captured||0)*100/x.total)):null;
  if(!x||x.phase==="unknown"){prog.textContent="";return;}
  const counts={title:x.title||tr("chat"),captured:(x.captured||0).toLocaleString(),total:(x.total||0).toLocaleString(),percent};
  if(running&&x.stage==="files")prog.textContent=tr("Exporting {title}: ",counts)+tr("{captured} messages saved; files: {done}/{total}",{captured:counts.captured,done:(x.files_done||0).toLocaleString(),total:(x.files_total||0).toLocaleString()})+
    (x.eta_seconds!==null&&x.eta_seconds!==undefined?" · "+tr("{time} left",{time:fmtDuration(x.eta_seconds)}):"")+"…";
  else if(running)prog.textContent=tr("Exporting {title}: ",counts)+tr(x.total?"{captured} of {total} messages ({percent}%)":"{captured} messages read",counts)+
    (x.eta_seconds!==null&&x.eta_seconds!==undefined?" · "+tr("{time} left",{time:fmtDuration(x.eta_seconds)}):"")+"…";
  else if(x.phase==="done")prog.textContent=tr("Done: {captured} messages. Download the signed bundle.",counts);
  else if(x.phase==="failed")prog.textContent=tr("Export failed")+(x.error?" ("+x.error+")":"")+". "+tr("Try again.");
  else if(x.phase==="cancelled")prog.textContent=tr("Export cancelled.");
}
async function pollExport(id){
  const profile=state.profile,revision=state.workspaceRevision;
  const current=()=>profile===state.profile&&revision===state.workspaceRevision&&id===state.exportId;
  if(!current())return;
  stopExportPoll();
  try{
    const x=await json("chat-export/"+encodeURIComponent(id),undefined,{profile});
    if(!current())return;
    renderExportState(x);
    if(x.phase==="running")exportPoll=setTimeout(()=>{if(current())pollExport(id);},1500);
    else{state.exportId=x.phase==="done"?id:null;state.exportName=x.filename;}
  }catch(e){if(e instanceof StaleView||!current())return;renderExportState({phase:"failed",error:e.message});state.exportId=null;}
}
function syncExport(s){
  const btn=$("chat-export-form").querySelector("button[type=submit]"),x=s.collector.chat_export;
  btn.disabled=s.demo||!s.collector.has_session||!s.targets.length||!!(x&&x.phase==="running");
  if(state.exportId||exportPoll)return;
  if(!x){renderExportState(null);return;}
  if(x.phase==="running"){state.exportId=x.id;renderExportState(x);pollExport(x.id);}
  else if(x.phase==="done"){state.exportId=x.id;state.exportName=x.filename;renderExportState(x);}
  else renderExportState(x);
}
$("chat-export-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const chat_id=Number($("chat-export-source").value),language=exportLanguage();
  if(!chat_id)throw new Error(tr("Select a source to export."));
  const files=$("chat-export-files").value||null;
  const x=await json("chat-export/start",{chat_id,...(language?{language}:{}),...(files?{files}:{})});
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
  if(await download("chat-export/"+encodeURIComponent(state.exportId)+"/download",state.exportName,true)===false)return;
  if(revision!==state.workspaceRevision)return;
  toast(tr("Signed chat export downloaded."));
  show("chat-export-download",false);state.exportId=null;
  $("chat-export-progress").textContent=tr("Downloaded. Export another chat if needed.");
});}
$("chat-export-download").addEventListener("click",e=>saveExport(e.currentTarget));
const accountExportKinds=["private","bot","group","supergroup","channel"];
const accountExportMedia=["photo","video","video_message","voice","audio","document","sticker","animation"];
const accountExportFallback={purpose:"",chat_kinds:accountExportKinds,from_utc:null,to_utc:null,chat_ids:[],
  report_language:'en',export_format:'tgwitness',budget_exhausted:'hashes_only',
  sender_ids:[],text_contains:[],own_messages_only:false,
  include_archived:true,media_types:accountExportMedia,max_media_file_mib:512,max_total_gib:16,
  include_profile:true,include_contacts:true,include_profile_photos:false,include_stories:false,
  include_session_metadata:false,include_other_data:false,transport:"takeout"};
let accountExportRead=null,accountExportRequest=0,accountExportJobStamp=null;
for(const id of ['account-export-language','account-disclosure-language']){
  for(const [code,name] of Object.entries(PANEL_LANGUAGES)){
    const option=new Option(name,code);option.lang=code;option.defaultSelected=code==='en';$(id).append(option);
  }
}
function resetAccountExport(){
  accountExportRequest++;accountExportRead=null;accountExportJobStamp=null;disclosurePreview?.clear();
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
  $('account-export-format').value=saved.export_format||'tgwitness';
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
  $("account-export-media-action").value=saved.media_action||"download";
  $("account-export-oversized").value=saved.oversized_media||"exclude";
  for(const select of $('account-export-media-actions').querySelectorAll('select'))
    select.value=saved.media_actions?.[select.dataset.mediaKind]||'';
  $("account-export-total-limit").value=String(saved.max_total_gib);
  $("account-export-budget-action").value=saved.budget_exhausted||'hashes_only';
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
  return {purpose,report_language:$('account-export-language').value,export_format:$('account-export-format').value,
    budget_exhausted:$('account-export-budget-action').value,chat_kinds:kinds,from_utc,to_utc,chat_ids,sender_ids,text_contains,
    own_messages_only:$("account-export-own").checked,
    include_archived:$("account-export-archived").checked,
    media_types:[...$("account-export-media").querySelectorAll("input:checked")].map(n=>n.value),
    media_action:$("account-export-media-action").value,oversized_media:$("account-export-oversized").value,
    media_actions:Object.fromEntries([...$('account-export-media-actions').querySelectorAll('select')].filter(select=>select.value).map(select=>[select.dataset.mediaKind,select.value])),
    max_media_file_mib,max_total_gib,include_profile:$("account-export-profile").checked,
    include_contacts:$("account-export-contacts").checked,
    include_profile_photos:$("account-export-profile-photos").checked,
    include_stories:$("account-export-stories").checked,
    include_session_metadata:$("account-export-session-metadata").checked,
    include_other_data:$("account-export-other-data").checked,transport:$("account-export-transport").value};
}
for(const [kind,label] of Object.entries({photo:'Photos',video:'Videos',video_message:'Video messages',voice:'Voice messages',audio:'Audio',document:'Documents',sticker:'Stickers',animation:'Animations'})){
  const wrapper=node('div'),select=node('select'),caption=node('label','',tr(label));
  select.id='account-export-action-'+kind;select.dataset.mediaKind=kind;caption.htmlFor=select.id;
  for(const [value,text] of [['','Use selected media action'],['download','Download files'],['hashes_only','Save server hashes only'],['exclude','Keep message metadata only']]){
    const option=node('option','',tr(text));option.value=value;select.append(option);
  }
  wrapper.append(caption,select);$('account-export-media-actions').append(wrapper);
}
function renderAccountExportPreview(){
  const box=$("account-export-preview");
  $("account-export-preflight-result").textContent=tr("Check the current settings to read a bounded sample. Final size and time may remain unknown.");
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
      tr({download:"Selected files will be downloaded.",hashes_only:"Only server hash ranges will be saved; file bytes will not be downloaded.",exclude:"Message media will remain metadata only."}[x.media_action])+" "+
      (Object.keys(x.media_actions).length?tr('Per-type overrides: {settings}.',{settings:Object.entries(x.media_actions).map(([kind,action])=>
        $('account-export-action-'+kind).previousElementSibling.textContent+': '+tr({download:'Download files',hashes_only:'Save server hashes only',exclude:'Keep message metadata only'}[action])).join('; ')})+' ':'')+
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
window.addEventListener("tgwitness:time-zone",()=>{accountExportJobStamp=null;if(state.view==="evidence")renderAccountExportJobs();});
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
function accountExportWaiting(job){return job.phase==='waiting'&&!!job.wait_until&&new Date(accountExportEpochMs(job.wait_until)).valueOf()>Date.now();}
function accountExportNextStep(job){
  if(job.ready)return '';
  if(job.phase==='waiting'&&job.active===false&&job.wait_reason==='rate_limit')return tr(accountExportWaiting(job)?
    'Telegram has limited requests. Keep the saved progress and resume after the displayed deadline.':
    'Progress is saved. Choose Resume to continue this job.');
  if(job.phase==='waiting')return tr(job.active!==false?
    'Telegram has asked this job to wait. It will continue automatically while TgWitness is running.':accountExportWaiting(job)?
    'Open Telegram on another device that was signed in before this request and allow this export. The requesting session and a fresh login cannot approve it. Then choose Check approval, or keep this session and resume after the displayed deadline.':
    'Progress is saved. Choose Resume to continue this job.');
  if(job.phase==='paused')return tr('Progress is saved. Choose Resume to continue this job.');
  if(job.phase==='failed')return tr('Review the error below, then choose Resume to retry from saved progress.');
  if(job.phase==='packaging')return tr('The archive is being packaged and signed. Download will appear here when it is ready.');
  if(job.active!==false&&['preparing','running'].includes(job.phase))
    return tr('This job continues while TgWitness is running. You can leave this page and return.');
  return '';
}
function accountDisclosureFilename(item){return 'tgwitness-disclosure-'+String(item.id).replace(/[^a-zA-Z0-9_-]/g,'')+'.zip';}
function accountDisclosureRecipientNote(item){
  return [tr('File: {filename}',{filename:accountDisclosureFilename(item)}),
    tr('Extract the ZIP and open index.html to read this sharing copy. Review its scope, omissions and disclosure settings.'),
    tr('Keep the ZIP unchanged. Follow README.txt to check its integrity using a signing-key fingerprint obtained independently from the sender.'),
    tr('TgWitness signs these files with the collector key; any change to a file breaks the signature.')].join('\n\n');
}
function renderAccountExportJobs(){
  const box=$("account-export-jobs"),focused=document.activeElement,
    action=focused?.dataset?.accountExportAction,jobId=focused?.dataset?.jobId,disclosureId=focused?.dataset?.disclosureId;
  const jobs=state.accountExportJobs;
  renderExportJobLink();
  const stamp=JSON.stringify([jobs,state.accountDisclosures,jobs.map(accountExportWaiting)]);
  if(accountExportJobStamp===stamp)return;
  accountExportJobStamp=stamp;
  const openDetails=new Set([...box.querySelectorAll('details[open]')].map(el=>el.dataset.exportDetail));
  const selection=focused?.tagName==='TEXTAREA'?[focused.selectionStart,focused.selectionEnd]:null;
  box.replaceChildren();
  if(!jobs.length){box.append(node("p","account-export-empty",tr("No account exports yet. Configure one to save the history this account can currently read.")));return;}
  const identify=(element,job,kind,disclosure)=>{
    element.dataset.accountExportAction=kind;element.dataset.jobId=job.id;
    if(disclosure)element.dataset.disclosureId=disclosure.id;return element;
  };
  const addAction=(parent,job,label,kind,work,cls="secondary",disclosure)=>{
    const b=node("button",cls,label);b.type="button";
    identify(b,job,kind,disclosure);b.addEventListener("click",async()=>{
      const restore=document.activeElement===b;
      await busy(b,work);
      if(restore&&document.activeElement===document.body){
        const replacement=[...box.querySelectorAll('[data-account-export-action]')].find(element=>
          element.dataset.accountExportAction===kind&&element.dataset.jobId===job.id&&
          (element.dataset.disclosureId||'')===(disclosure?.id||''));
        (b.isConnected?b:replacement)?.focus();
      }
    });parent.append(b);return b;
  };
  for(const job of jobs){
    const phase=job.phase||"unknown",counts=job.counts||{},coverage=job.coverage||{};
    const card=node("article","account-export-job"),head=node("div","account-export-job-head");
    head.append(node("strong","",tr("Account export {id}",{id:String(job.id||"").slice(0,10)})),
      node("span","account-export-state "+phase,accountExportPhase(phase)));
    card.append(head);
    const when=accountExportTime(job.created_at);
    if(when)card.append(node("p","account-export-job-sub",tr("Started {time}",{time:when})));
    const next=accountExportNextStep(job);
    if(next)card.append(node('p','account-export-next',next));
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
    metric(tr("messages saved"),Math.max(counts.messages_exported||0,job.acquisition?.messages_preserved||0));
    metric(tr("media saved"),counts.media_saved);
    metric(tr("files with hashes"),counts.media_hashed);
    metric(tr("media skipped"),counts.media_skipped);
    if(Number.isFinite(counts.unique_media_bytes))metric(tr("unique file bytes saved"),counts.unique_media_bytes);
    else if(Number.isFinite(counts.bytes_saved))metric(tr("bytes saved"),counts.bytes_saved);
    if(facts.childNodes.length)card.append(facts);
    const transfer=job.active!==false&&job.transfer;
    if(transfer){
      const received=humanSize(transfer.received_bytes),total=transfer.total_bytes==null?tr('Unknown'):humanSize(transfer.total_bytes);
      card.append(node('p','account-export-transfer',tr('Current file: {received} received of {total}. Preserved after the download completes.',{received,total})));
    }
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
      details.dataset.exportDetail=job.id+':omissions';identify(summary,job,'omissions');
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
      waitPending=accountExportWaiting(job);
    if(active&&phase!=="packaging")addAction(actions,job,tr("Pause"),"pause",()=>accountExportAction(job,"pause"),"quiet");
    if(!job.ready&&(["paused","failed"].includes(phase)||(phase==="waiting"&&!active&&(job.wait_reason!=="rate_limit"||!waitPending))))
      addAction(actions,job,tr(phase==="waiting"&&waitPending?"Check approval":"Resume"),"resume",()=>accountExportAction(job,"resume"));
    if(!job.ready&&!active&&["paused","waiting","failed"].includes(phase))
      addAction(actions,job,tr("Finish with saved data"),"finish",async()=>{
        const owner=actionOwner();
        if(!(await askConfirm(tr("Create an archive from the data already saved? Missing data will be listed, and this job will no longer resume."),
          {confirmText:tr("Finish with saved data")}))||!owner.current())return;
        await accountExportAction(job,"finish");
      },"quiet");
    if(job.ready){
      const original=node('section','account-export-original');
      original.append(node('h3','',tr('Original account archive')),
        node('p','',tr('Download and keep this original. Extract the ZIP and open index.html to review what was saved and what is missing.')));
      addAction(actions,job,tr('Download original archive'),'download',()=>accountExportDownload(job),'primary');
      addAction(actions,job,tr('Prepare a sharing copy'),'disclosure',()=>openAccountDisclosure(job));
      original.append(actions);card.append(original);
    }else card.append(actions);
    const saved=state.accountDisclosures[job.id]||[];
    const persisted=Array.isArray(job.disclosures)?job.disclosures:[];
    const disclosures=[...persisted,...saved.filter(local=>!persisted.some(item=>item.id===local.id))];
    if(disclosures.length){
      const derivatives=node("div","account-disclosure-list");
      derivatives.append(node("strong","",tr("Signed sharing copies")));
      derivatives.append(node('p','hint',tr('Separate files made from the original. Review each full copy before sending it.')));
      for(const item of disclosures){
        const row=node("section","account-disclosure-item"),heading=node('div','account-disclosure-item-head'),
          label=node('strong','',tr('Sharing copy {id}',{id:String(item.id||'').slice(0,10)}));
        heading.append(label);row.append(heading);
        if(item.ready){
          addAction(heading,job,tr('Download sharing copy'),'disclosure-download',()=>accountDisclosureDownload(job,item),'secondary',item);
          const handoff=node('details','account-export-handoff'),summary=node('summary','',tr('Review & hand off'));
          handoff.dataset.exportDetail=job.id+':handoff:'+item.id;identify(summary,job,'handoff',item);
          const steps=node('ol');
          for(const text of [tr('Download this copy. Extract the ZIP and open index.html.'),
            tr('Review the full report and included files for personal information, context and omissions.'),
            tr('Send the reviewed ZIP with the recipient note below. Keep your original archive separately.')])steps.append(node('li','',text));
          const note=identify(node('textarea','recipient-note'),job,'recipient-note',item);
          note.readOnly=true;note.rows=6;note.value=accountDisclosureRecipientNote(item);note.setAttribute('aria-label',tr('Recipient note'));
          const noteActions=node('div','account-export-job-actions');
          addAction(noteActions,job,tr('Copy recipient note'),'recipient-copy',async()=>{
            try{await navigator.clipboard.writeText(note.value);toast(tr('Recipient note copied.'));}
            catch{note.focus();note.select();toast(tr('Could not copy. Select and copy the recipient note.'),true);}
          },'quiet',item);
          handoff.append(summary,steps,note,noteActions);row.append(handoff);
        }else row.append(node("span","hint",tr("Preparing signed derivative")));
        derivatives.append(row);
      }
      card.append(derivatives);
    }
    if(!active){const management=node('div','account-export-management');
      addAction(management,job,tr('Delete job'),'delete',()=>accountExportDelete(job),'quiet');card.append(management);}
    box.append(card);
  }
  for(const details of box.querySelectorAll('details'))details.open=openDetails.has(details.dataset.exportDetail);
  if(action&&jobId){const replacement=[...box.querySelectorAll("[data-account-export-action]")].find(n=>
    n.dataset.accountExportAction===action&&n.dataset.jobId===jobId&&n.dataset.disclosureId===disclosureId);
    replacement?.focus({preventScroll:true});if(selection&&replacement?.tagName==='TEXTAREA')replacement.setSelectionRange(...selection);}
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
    $("account-export-start").disabled=state.accountExportCapabilities.can_start===false||state.status?.collector.available_for_export===false||
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
  const owner=actionOwner();
  if(!(await askConfirm(tr("Delete this account export job, its archive and its disclosures? This cannot be undone."),{danger:true,confirmText:tr("Delete")})))return;
  if(!owner.current())return;
  await api("account-export/"+encodeURIComponent(job.id),undefined,{profile:owner.profile,token:owner.token,method:"DELETE"});
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
    await openWorkflowSignIn();return;
  }
  await loadAccountExport();if(!current())return;$('account-export-dialog').showModal();
  $("account-export-dialog-title").focus?.();
}));
$("account-export-refresh").addEventListener("click",e=>busy(e.currentTarget,()=>loadAccountExport()));
$("account-export-close").addEventListener("click",()=>$("account-export-dialog").close());
$("account-export-dismiss").addEventListener("click",()=>$("account-export-dialog").close());
$("account-export-form").addEventListener("input",()=>{state.accountExportDirty=true;renderAccountExportPreview();});
$("account-export-form").addEventListener("change",()=>{state.accountExportDirty=true;renderAccountExportPreview();});
$("account-export-preflight").addEventListener("click",event=>busy(event.currentTarget,async()=>{
  const options=accountExportOptions(),stamp=JSON.stringify(options),profile=state.profile,revision=state.workspaceRevision;
  const box=$("account-export-preflight-result");box.textContent=tr("Checking settings and reading a bounded sample…");
  const result=await json("account-export/preflight",options);
  if(profile!==state.profile||revision!==state.workspaceRevision)return;
  try{if(JSON.stringify(accountExportOptions())!==stamp)return;}catch{return;}
  const sample=result.sample||{},mib=bytes=>(Number(bytes||0)/1048576).toFixed(2);
  const lines=[tr(result.can_start?"Settings checked.":"Review the blocking issues before starting."),
    tr("Free disk: {n} MiB.",{n:mib(result.free_disk_bytes)})];
  if(sample.messages_examined)lines.push(tr("Sample: {messages} messages in {chats} chats. Selected file bytes: {files} MiB. Estimated hash manifest: {hashes} MiB.",
    {messages:sample.messages_examined,chats:sample.sampled_chats,files:mib(sample.known_download_bytes),hashes:mib(sample.hash_manifest_estimate_bytes)}));
  for(const issue of result.issues||[])lines.push(tr(issue.message));
  lines.push(tr("Total output size and completion time remain unknown. Reports and temporary files also require space."));
  box.textContent=lines.join(" ");
}));
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
    withheld_markers:$("account-disclosure-withheld").value,
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
async function openAccountDisclosure(job){
  if(!job.ready)throw new Error(tr("Finish the source archive before preparing a disclosure."));
  if(state.accountDisclosureJob!==job.id){
    if(state.accountDisclosureDirty&&!(await askConfirm(tr("Discard the unfinished disclosure settings?"))))return;
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
  const approved=state.accountDisclosurePreview,owner=actionOwner();
  if(!approved||approved.jobId!==state.accountDisclosureJob||approved.profile!==state.profile||
      approved.revision!==state.workspaceRevision||approved.policyRevision!==accountDisclosurePolicyRevision)
    throw new Error(tr("Preview the current disclosure settings before creating a file."));
  if(approved.expires_at&&Date.now()>=new Date(accountExportEpochMs(approved.expires_at)).valueOf()){
    accountDisclosureInvalidate();throw new Error(tr("The disclosure preview expired. Preview the settings again."));
  }
  if(!(await askConfirm(tr("Create a signed derivative from this preview? Personal information may still remain; review the file before sharing."))))return;
  if(!owner.current()||state.accountDisclosurePreview!==approved||approved.jobId!==state.accountDisclosureJob||
      approved.policyRevision!==accountDisclosurePolicyRevision)return;
  const jobId=approved.jobId,profile=approved.profile,revision=approved.revision,context=viewContexts.get('evidence');
  const result=await json("account-export/"+encodeURIComponent(jobId)+"/disclosure",{preview_id:approved.id},{profile,token:owner.token});
  if(profile!==state.profile||revision!==state.workspaceRevision||jobId!==state.accountDisclosureJob)return;
  if(!result?.id)throw new Error(tr("Disclosure creation did not return a derivative ID."));
  (state.accountDisclosures[jobId]??=[]).unshift(result);
  state.accountDisclosureDirty=false;state.accountDisclosurePreview=null;
  $("account-disclosure-create").disabled=true;$("account-disclosure-dialog").close();
  await loadAccountExport();
  if(profile!==state.profile||revision!==state.workspaceRevision)return;
  if(state.view==='evidence'&&state.exportTask==='account'&&context?.current())
    [...$('account-export-jobs').querySelectorAll('[data-account-export-action="disclosure-download"]')]
      .find(button=>button.dataset.jobId===jobId&&button.dataset.disclosureId===result.id)?.focus();
  toast(tr('Sharing copy created. Download it below, then review it before sharing.'));
}
async function accountDisclosureDownload(job,item){
  if(!item.ready)throw new Error(tr("This disclosure is still being prepared."));
  const path="account-export/"+encodeURIComponent(job.id)+"/disclosures/"+encodeURIComponent(item.id)+"/download";
  if(await download(path,accountDisclosureFilename(item),true))
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
const exportsReady=import('./views/exports.js?v=2').then(({createExports})=>{
  exportsView=createExports({root:$("view-evidence"),tr,json,getSession:()=>state.workspaceRevision+":"+state.profile,fmtTime,toast,
    downloadAgain:entry=>download('exports/'+entry.id+'/download','tgwitness-'+entry.id.slice(0,8)+'.'+(entry.encrypted?(entry.encryption||'zip'):entry.format),true)});
  return exportsView;
});
async function loadExports(){fillExportLanguage();return (await exportsReady).enter(viewOptions('evidence'));}
function fillExportLanguage(){
  const select=$("export-language");if(select.options.length)return;
  select.append(new Option(tr("As in Report settings"),""));
  for(const [code,name] of Object.entries(PANEL_LANGUAGES)){const o=new Option(name,code);o.lang=code;select.append(o);}
}
const exportLanguage=()=>$("export-language").value;
async function download(path,filename,stream=false,root=false,body=undefined,progress=()=>{},{confirmWorkspace=true,owner=null}={}){
  workspaceSafety?.assert();
  const profile=state.profile,revision=state.workspaceRevision,token=state.token;
  if(confirmWorkspace&&(/export|handover|history\/report/.test(path))&&!path.startsWith('profile-groups/')&&!(await workspaceSafety.confirmExport())){progress({phase:'cancelled'});return false;}
  const current=()=>{if(profile!==state.profile||revision!==state.workspaceRevision||token!==state.token||owner&&!owner.current())throw new StaleView();workspaceSafety?.assert();};
  let handle=null,writer=null,reader=null;
  if(stream&&typeof window.showSaveFilePicker==="function"){
    try{handle=await window.showSaveFilePicker({suggestedName:filename});}
    catch(error){if(error.name==="AbortError"){progress({phase:"cancelled"});return false;}handle=null;}
  }
  current();
  if(handle){try{writer=await handle.createWritable();}catch{handle=null;}}
  let response;
  try{current();response=await api(path,body,root?{root:true,token}:{profile,token});}
  catch(error){await writer?.abort().catch(()=>{});throw error;}
  const expected=Number(response.headers.get("Content-Length")||0);
  const preparedId=response.headers.get('X-TgWitness-Export-ID');
  const jobTicket=response.headers.get('X-TgWitness-Download-Ticket');
  const ticketPath=preparedId?'exports/'+preparedId+'/ticket':jobTicket;
  const limit=(state.status?.parameters?.browser_buffer_mib||128)*1024*1024;
  let nativeAttempted=false;
  async function nativeDownload(){
    current();nativeAttempted=true;
    const ticket=await json(ticketPath,{},root?{root:true,token}:{profile,token});current();
    const target=new URL(ticket.url,location.origin);
    if(target.origin!==location.origin)throw new Error(tr('The download address is invalid. Prepare the export again.'));
    const link=node('a');link.href=target.href;link.download=filename;document.body.append(link);link.click();link.remove();
    progress({phase:'browser',total:expected,expected});void exportsView?.load();
    toast(tr(preparedId?'Download started. Check your browser’s downloads. The file is also in Prepared exports.':
      'Download started. Check your browser’s downloads.'));return true;
  }
  try{
    current();
    if(!writer&&expected>limit){
      await response.body?.cancel();
      if(ticketPath)return await nativeDownload();
      const error=new Error(tr('This file is too large for this browser. Use a browser with file streaming or download from the local command line.'));
      error.downloadHint=true;throw error;
    }
    reader=response.body.getReader();
    let total=0;const chunks=[];
    while(true){
      current();
      const {value,done}=await reader.read();current();if(done)break;
      total+=value.byteLength;
      if(writer)await writer.write(value);
      else{if(total>limit)throw new Error(tr('Browser memory limit reached. Download the prepared file again.'));chunks.push(value);}
      progress({phase:"saving",total,expected});
      if(stream){const size=(total/1024**2).toFixed(1)+" MiB"+(expected?" / "+(expected/1024**2).toFixed(1)+" MiB":"");toast(tr("Saving export: {size}",{size}));}
    }
    if(expected&&total!==expected)throw new Error(tr("Download was interrupted. Retry the export."));
    current();if(writer){await writer.close();writer=null;}
    else saveBlob(new Blob(chunks,{type:response.headers.get("Content-Type")||"application/octet-stream"}),filename);
    progress({phase:"done",total,expected});
    if(stream)toast(tr(handle?'File saved.':'Download started. Check your browser’s downloads.'));
    return true;
  }catch(error){
    if(reader)await reader.cancel().catch(()=>{});else await response.body.cancel().catch(()=>{});
    if(writer)await writer.abort().catch(()=>{});
    if(!(error instanceof StaleView)&&ticketPath&&!nativeAttempted){current();return await nativeDownload();}
    if(error instanceof StaleView)throw error;
    if(nativeAttempted)throw error;
    if(error.downloadHint)throw error;
    throw new Error(tr('The browser could not save the file. Open Prepared exports and choose Download again.'));
  }
}
function saveBlob(blob,filename){
  const url=URL.createObjectURL(blob),a=node("a");a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
}
panelQueries("[data-export]").forEach(b=>b.addEventListener("click",()=>busy(b,async()=>{
  const fmt=b.dataset.export,password=$("export-password").value;
  const encrypt=!!b.closest("#view-evidence")&&$("export-encrypt-on").checked;
  if(encrypt&&password.length<12){$("export-password").focus();throw new Error(tr("Enter a password of at least 12 characters, or untick encryption."));}
  const encryption=$("export-encryption").value;
  const progress=(await exportsReady).begin({format:fmt,encrypted:encrypt,encryption,retry:()=>b.click()}),language=exportLanguage();
  const query=language?"?language="+encodeURIComponent(language):"",name=fmt==="json"||fmt==="pdf"?"tgwitness-report."+fmt:"tgwitness-evidence."+fmt;
  try{
    const saved=await download("export/"+fmt+query,encrypt?"tgwitness-evidence-"+fmt+"-encrypted."+encryption:name,true,false,encrypt?{password,encryption}:undefined,progress);
    if(saved)toast(tr(encrypt?"Encrypted export sent to your browser. Keep its password separately.":"Export sent to your browser. Check Downloads for the saved file."));
  }catch(error){progress({phase:"failed",error:error.message});throw error;}
})));
const REPORT_FIELDS={"report-language":"language","report-theme":"theme","report-case-title":"case_title",
  "report-case-board":"case_board",
  "report-case-id":"case_id","report-examiner":"examiner","report-organization":"organization","report-notes":"notes",
  "report-part-size":"part_size","report-participant-labels":"participant_labels","report-chart-limit":"chart_limit",
  "report-review-question":"review_question","report-review-method":"review_method",
  "report-review-findings":"review_findings","report-review-conclusion":"review_conclusion"};
const REPORT_CHECKS={"report-timeline":"timeline","report-raw":"raw_records","report-media":"media_previews",
  "report-heartbeats":"group_heartbeats","report-changes":"show_changes","report-indicators":"show_indicators","report-composition-chart":"composition_chart","report-activity-chart":"activity_chart","report-hourly-chart":"hourly_chart",
  "report-participant-chart":"participant_chart","report-chat-chart":"chat_chart"};
const REPORT_PRESETS={
  dossier:{timeline:true,raw_records:true,media_previews:true,group_heartbeats:true,
    activity_chart:true,hourly_chart:true,participant_chart:true,chat_chart:true,composition_chart:true,show_changes:true,show_indicators:true},
  brief:{timeline:false,raw_records:false,media_previews:false,group_heartbeats:true,
    activity_chart:true,hourly_chart:false,participant_chart:false,chat_chart:false,composition_chart:false,show_changes:false,show_indicators:false},
  activity:{timeline:false,raw_records:false,media_previews:false,group_heartbeats:true,
    activity_chart:true,hourly_chart:true,participant_chart:true,chat_chart:true,composition_chart:true,show_changes:true,show_indicators:true}
};
let reportSelection;
let reportGuidance;
const reportGuidanceReady=import('./views/report-guidance.js?v=1').then(({createReportGuidance})=>{
  reportGuidance=createReportGuidance({root:$("report-guidance"),tr});
  return reportGuidance;
});
const reportSelectionReady=import('./views/report-selection.js?v=1').then(({createReportSelection})=>{
  reportSelection=createReportSelection({root:$("report-form"),tr,json,
    getOwner:()=>state.workspaceRevision+":"+state.profile,
    ready:()=>reportReady&&reportOwner===reportKey()&&!reportSaving&&state.view==='evidence',
    options:reportDraft,active:()=>state.view==='evidence'});
  return reportSelection;
});
const reportTemplate=()=>$("report-form").querySelector('[name="report-template"]:checked')?.value||"custom";
let reportConfigurations;
const reportConfigurationsReady=import('./views/report-profiles.js?v=1').then(({createReportProfiles})=>{
  reportConfigurations=createReportProfiles({root:$("report-profiles"),tr,json,owner:reportKey,
    ready:()=>reportReady&&reportOwner===reportKey()&&!reportSaving&&state.view==='evidence',draft:reportDraft,run:busy,
    apply:options=>{
      for(const [id,key] of Object.entries(REPORT_FIELDS))if(Object.hasOwn(options,key))$(id).value=options[key];
      for(const [id,key] of Object.entries(REPORT_CHECKS))if(Object.hasOwn(options,key))$(id).checked=options[key];
      setReportDesign(options.design);setReportTemplate(options.template);
      discardReportDraft();$("report-theme").dispatchEvent(new Event('input',{bubbles:true}));
    }});
  return reportConfigurations;
});
const reportDesign=()=>$("report-form").querySelector('[name="report-design"]:checked')?.value||"classic";
function setReportDesign(value){
  const choices=[...$("report-form").querySelectorAll('[name="report-design"]')];
  const canonical=({dossier:"classic",analytical:"atlas",editorial:"quire"})[value]||value;
  const known=choices.some(input=>input.value===canonical)?canonical:"classic";
  choices.forEach(input=>{input.checked=input.value===known;});
}
function setReportTemplate(value){
  const known=Object.hasOwn(REPORT_PRESETS,value)||value==="custom"?value:"custom";
  $("report-form").querySelectorAll('[name="report-template"]').forEach(input=>{input.checked=input.value===known;});
}
let reportOwner=null,reportReady=false,reportDirty=false,reportRequest=0,reportLoading=null,reportSaving=false;
let reportPreviewRequest=0,reportPreviewTimer=null,reportPreviewBusy=false;
let reportPreviewSection="cover";
const reportKey=()=>state.workspaceRevision+":"+state.profile;
function resetReportSettings(){
  clearTimeout(reportPreviewTimer);reportPreviewRequest++;reportPreviewBusy=false;
  reportPreviewSection="cover";
  $("report-preview-frame").removeAttribute("srcdoc");show("report-preview-frame",false);show("report-preview-empty",true);
  delete $("report-preview-frame").dataset.reportDesign;
  $("report-design-preview-status").textContent=tr("Preview uses your draft. Save settings before exporting.");
  reportOwner=null;reportReady=false;reportDirty=false;reportRequest++;reportLoading=null;reportSaving=false;
  $("report-form").reset();$("report-fields").disabled=true;$("report-status").replaceChildren();
  $("report-outline").replaceChildren();$("report-form").querySelectorAll(".report-examination").forEach(el=>el.open=false);
  reportSelection?.reset();
  reportGuidance?.reset();
  reportConfigurations?.reset();
  $("report-form").querySelectorAll(".form-error").forEach(el=>el.remove());
}
function reportControls(){
  $("report-fields").disabled=!reportReady||reportOwner!==reportKey()||reportSaving||!!window.TGW_ONLINE_DEMO;
  $("report-preview-refresh").disabled=reportPreviewBusy;
  syncReportParts();
}
async function loadReportSettings(){
  if(!state.status)return;
  await Promise.all([reportSelectionReady,reportConfigurationsReady,reportGuidanceReady]);
  const owner=reportKey();
  if(reportOwner!==owner){resetReportSettings();reportOwner=owner;}
  if(reportSaving||reportReady&&reportDirty)return;
  if(reportLoading)return reportLoading;
  const request=++reportRequest,current=()=>reportOwner===owner&&reportKey()===owner&&request===reportRequest;
  reportReady=false;reportControls();$("report-status").textContent=tr("Loading…");
  const pending=(async()=>{
    try{
      const [options,guidance]=await Promise.all([json("report-options",undefined,viewOptions('evidence')),json("report-guidance",undefined,viewOptions('evidence'))]);if(!current()||state.view!=='evidence')return;
      const select=$("report-language");
      if(!select.options.length){
        select.append(new Option(tr("Same as the panel"),"auto"));
        for(const [code,name] of Object.entries(PANEL_LANGUAGES)){const o=new Option(name,code);o.lang=code;select.append(o);}
      }
      for(const [id,key] of Object.entries(REPORT_FIELDS))$(id).value=options[key]??({participant_labels:"aliases",chart_limit:10}[key]??"");
      for(const [id,key] of Object.entries(REPORT_CHECKS))$(id).checked=options[key]??REPORT_PRESETS.dossier[key];
      const template=options.template||"dossier",preset=REPORT_PRESETS[template];
      const matches=preset&&Object.entries(REPORT_CHECKS).every(([id,key])=>$(id).checked===preset[key])
        &&$("report-participant-labels").value==="aliases"&&$("report-chart-limit").valueAsNumber===10;
      setReportTemplate(matches?template:"custom");
      setReportDesign(options.design);
      reportSelection.load(options.selection);
      reportGuidance.load(options.jurisdiction_guidance,guidance);
      reportReady=true;reportDirty=false;formControls?.loaded("report-form");$("report-status").textContent=window.TGW_ONLINE_DEMO?tr("Sample data"):"";
      await reportConfigurations.load();if(!current()||state.view!=='evidence')return;
      if(!$("report-form").hidden&&!$("report-preview-frame").hasAttribute("srcdoc"))scheduleReportPreview();
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
function syncReportParts(){
  $("report-raw").disabled=$("report-heartbeats").disabled=!$("report-timeline").checked;
  $("report-participant-labels").disabled=!$("report-participant-chart").checked;
  $("report-chart-limit").disabled=!$("report-participant-chart").checked&&!$("report-chat-chart").checked;
  const parts=[tr("Case details")];
  const guidanceActive=reportGuidance?.sync();
  if(guidanceActive)parts.push(tr("Jurisdiction guidance"));
  const guidanceTab=$("report-form").querySelector('[data-preview-section="guidance"]');
  guidanceTab.hidden=!guidanceActive;
  if(!guidanceActive&&reportPreviewSection==='guidance')showReportPreviewSection('cover');
  if(["question","method","findings","conclusion"].some(key=>$("report-review-"+key).value.trim()))parts.push(tr("Examination notes"));
  if($("report-activity-chart").checked)parts.push(tr("Activity over time"));
  if($("report-hourly-chart").checked)parts.push(tr("Activity by weekday and hour"));
  if($("report-participant-chart").checked)parts.push(tr("Participant activity"));
  if($("report-chat-chart").checked)parts.push(tr("Activity by chat"));
  if($("report-changes").checked)parts.push(tr("Changed and deleted message histories"));
  if($("report-indicators").checked)parts.push(tr("Links and technical indicators"));
  if($("report-timeline").checked)parts.push(tr("Record transcript"));
  if($("report-media").checked)parts.push(tr("Photo previews"));
  if($("report-composition-chart").checked)parts.push(tr("Record composition"));
  $("report-outline").replaceChildren(...parts.map(text=>node("li","",text)));
}
function applyReportPreset(){
  const preset=REPORT_PRESETS[reportTemplate()];
  if(preset){
    for(const [id,key] of Object.entries(REPORT_CHECKS))$(id).checked=preset[key];
    $("report-participant-labels").value="aliases";$("report-chart-limit").value="10";
  }
}
function reportDraft(){
  const body={template:reportTemplate(),design:reportDesign()};
  for(const [id,key] of Object.entries(REPORT_FIELDS))body[key]=$(id).value;
  body.part_size=$("report-part-size").valueAsNumber;body.chart_limit=$("report-chart-limit").valueAsNumber;
  body.selection=reportSelection?.read();
  body.jurisdiction_guidance=reportGuidance?.read();
  for(const [id,key] of Object.entries(REPORT_CHECKS))body[key]=$(id).checked;
  return body;
}
function scheduleReportPreview(){
  clearTimeout(reportPreviewTimer);
  reportPreviewTimer=setTimeout(()=>refreshReportPreview(),900);
}
function discardReportDraft(){
  clearTimeout(reportPreviewTimer);reportPreviewRequest++;reportPreviewBusy=false;
  $("report-preview-frame").removeAttribute("srcdoc");show("report-preview-frame",false);show("report-preview-empty",true);
  syncReportParts();reportControls();$("report-status").textContent="";
  $("report-design-preview-status").textContent=tr("Preview is updating to your draft…");scheduleReportPreview();
}
function showReportPreviewSection(section){
  reportPreviewSection=section;
  $("report-form").querySelectorAll('[data-preview-section]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.previewSection===section)));
  const frame=$("report-preview-frame");
  if(frame.hidden)return;
  if(section==='analytics')frame.contentDocument?.getElementById('report-analytics')?.scrollIntoView({block:'start'});
  else if(section==='guidance')frame.contentDocument?.getElementById('jurisdiction-guidance')?.scrollIntoView({block:'start'});
  else frame.contentWindow?.scrollTo(0,0);
}
$("report-preview-frame").addEventListener('load',()=>showReportPreviewSection(reportPreviewSection));
$("report-form").querySelectorAll('[data-preview-section]').forEach(button=>button.addEventListener('click',()=>showReportPreviewSection(button.dataset.previewSection)));
async function refreshReportPreview(){
  clearTimeout(reportPreviewTimer);
  if(!reportReady||reportOwner!==reportKey()||$("report-form").hidden||window.TGW_ONLINE_DEMO)return;
  if(!$("report-form").checkValidity()){
    $("report-design-preview-status").textContent=tr("Complete the required fields to update the preview.");return;
  }
  const body=reportDraft();
  if(!$("report-form").checkValidity()){
    $("report-design-preview-status").textContent=tr("Complete the required fields to update the preview.");return;
  }
  const owner=reportOwner,snapshot=JSON.stringify(body),request=++reportPreviewRequest;
  const current=()=>owner===reportOwner&&owner===reportKey()&&request===reportPreviewRequest;
  reportPreviewBusy=true;reportControls();$("report-design-preview-status").textContent=tr("Preparing preview…");
  try{
    const result=await json("report-design-preview",body,viewOptions('evidence'));
    if(!current()||snapshot!==JSON.stringify(reportDraft())||state.view!=='evidence')return;
    $("report-preview-frame").dataset.reportDesign=body.design;
    $("report-preview-frame").srcdoc=result.html;show("report-preview-frame",true);show("report-preview-empty",false);
    $("report-design-preview-status").textContent=tr(result.sampled?"Draft preview · first 50,000 records · not signed":"Draft preview · {n} records · not signed",{n:result.records.toLocaleString()});
  }catch(error){
    if(!current()||error instanceof StaleView||error.name==='AbortError')return;
    $("report-design-preview-status").textContent=tr("Preview failed. Update to retry.")+" "+error.message;
  }finally{if(current()){reportPreviewBusy=false;reportControls();}}
}
$("report-preview-refresh").addEventListener("click",refreshReportPreview);
$("exports-tab-settings").addEventListener("click",()=>{if(reportReady&&!$("report-preview-frame").hasAttribute("srcdoc"))scheduleReportPreview();});
$("report-form").addEventListener("input",event=>{if(reportReady&&!event.target.closest('#report-profiles')&&!event.target.matches("[data-report-search]")){
  reportSelection?.changed(event);
  if(event.target.name==="report-template")applyReportPreset();
  else if(Object.hasOwn(REPORT_CHECKS,event.target.id)||["report-participant-labels","report-chart-limit"].includes(event.target.id))setReportTemplate("custom");
  syncReportParts();reportDirty=true;$("report-status").textContent=tr("Draft changed. Save before exporting.");
  if(event.target.id.endsWith('-chart')||event.target.id==='report-chart-limit')reportPreviewSection='analytics';
  if(event.target.name==='report-design')reportPreviewSection='cover';
  $("report-design-preview-status").textContent=tr("Preview is updating to your draft…");scheduleReportPreview();
}});
$("report-form").addEventListener("change",event=>{syncReportParts();reportSelection?.changed(event);});
$("report-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  if(!reportReady||reportOwner!==reportKey()||reportSaving||window.TGW_ONLINE_DEMO)return;
  const owner=reportOwner,draft=formControls?.capture("report-form");
  const body=reportDraft();
  if(!$("report-form").reportValidity())return;
  reportSaving=true;reportControls();
  try{
    await json("report-options",body);if(reportOwner!==owner||reportKey()!==owner)return;
    reportDirty=formControls?.changed(draft)||false;formControls?.accepted(draft,reportDirty);$("report-status").textContent=tr(reportDirty?"Saved. New edits have not been saved.":"Saved. The next export uses these settings.");toast(tr("Report settings saved."));
  }finally{if(reportOwner===owner&&reportKey()===owner){reportSaving=false;reportControls();}}
});});
$("report-open-downloads").addEventListener("click",async()=>{
  if(reportDirty){$("report-status").textContent=tr("Save your changes before downloading a report with these choices.");$("report-status").scrollIntoView({block:"center"});return;}
  (await exportsReady).select('downloads');$("exports-downloads").scrollIntoView({block:"start"});
});
panelQueries("[data-go-reports]").forEach(link=>link.addEventListener("click",event=>{
  event.preventDefault();
  Promise.resolve(navigate("evidence")).then(()=>exportsReady).then(view=>{view.select("settings");
    const field=$(link.dataset.goReports==='data'?"report-data-title":"report-language");field.scrollIntoView({block:"center"});field.focus({preventScroll:true});});
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
  return facts.concat(witnessFacts(e));
}
function witnessFacts(e){
  const w=e.witnesses||{},facts=[],d=w.drand,v=w.devices;
  if(e.settings.drand&&d)facts.push(d.ok?tr("drand round {round} written to the journal · round time {time}",{round:String(d.round),time:fmtFull(d.round_time)})
    :tr("drand did not answer, {time}: {error}",{time:fmtFull(d.at),error:d.error}));
  if(e.settings.devices&&v)facts.push(v.ok?tr("Signed-in devices in Telegram: {n} · checked {time}",{n:v.count,time:fmtFull(v.at)})
    :tr("Telegram's device list could not be read, {time}: {error}",{time:fmtFull(v.at),error:tr(v.error)}));
  const g=w.gateway;
  if(e.settings.gateway&&!e.gateway?.has_token)facts.push(tr("Cloudflare Gateway log: set the account, location and token below."));
  else if(e.settings.gateway&&g)facts.push(g.ok?g.skipped?tr("Cloudflare Gateway log is up to date · checked {time}",{time:fmtFull(g.at)})
    :tr("Cloudflare Gateway log copied: {n} queries, up to {time}",{n:String(g.count),time:fmtFull(g.until)})
    :tr("Cloudflare Gateway log could not be copied, {time}: {error}",{time:fmtFull(g.at),error:g.error}));
  return facts;
}
function renderGateway(e){
  const g=e?.gateway,form=$("gateway-form");
  show("gateway-form",!!e&&($("evidence-gateway").checked||!!g?.has_token));
  if(!e||state.gatewayDirty)return;
  const value=g?.has_token?g:g?.suggested||{};
  $("gateway-account").value=value.account||"";$("gateway-location").value=value.location_id||"";
  $("gateway-address").value=value.address||"";$("gateway-token").value="";
  $("gateway-token").placeholder=g?.has_token?tr("Saved · leave empty to keep it"):"";
  show("gateway-remove",!!g?.has_token);
  $("gateway-status").textContent=g?.has_token?tr("Saved. Copied on each evidence pass while the option above is on."):
    g?.suggested?tr("Filled in from this server's deployment: add the token."):"";
  form.querySelectorAll("input,button").forEach(n=>n.disabled=!!state.status?.demo);
}
$("evidence-gateway").addEventListener("change",()=>show("gateway-form",$("evidence-gateway").checked||!!state.evidenceGateway?.has_token));
$("gateway-form").addEventListener("input",()=>{state.gatewayDirty=true;});
$("gateway-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const e=await json("evidence/gateway",{account:$("gateway-account").value.trim(),location_id:$("gateway-location").value.trim(),
    address:$("gateway-address").value.trim(),token:$("gateway-token").value.trim()});
  state.gatewayDirty=false;$("gateway-token").value="";renderEvidence(e);toast(tr("Cloudflare accepted these values. The log is copied on each evidence pass."));
});});
$("gateway-remove").addEventListener("click",ev=>busy(ev.currentTarget,async()=>{
  const e=await json("evidence/gateway",undefined,{method:"DELETE"});state.gatewayDirty=false;renderEvidence(e);
  toast(tr("Gateway log settings and token removed."));
}));
function renderEvidence(e){
  if(state.view!=='witness'&&!(state.view==='settings'&&$('evidence-form').closest('#view-settings')))return;
  const form=$("evidence-form"),status=$("evidence-status");
  form.querySelectorAll("input,select,textarea,button").forEach(n=>n.disabled=!e);
  state.timestampsHealth=e?.health||null;renderEvidenceBadge();
  if(!e){status.textContent=tr("Evidence mode works in a real workspace, not in the demo.");return;}
  if(state.evidenceProfile!==state.profile){state.evidenceDirty=false;state.evidenceProfile=state.profile;}
  if(!state.evidenceDirty){
    $("evidence-enabled").checked=e.settings.enabled;$("evidence-interval").value=String(e.settings.interval_minutes);
    $("evidence-tsa").value=e.settings.tsa_urls.join("\n");$("evidence-ots").value=e.settings.ots_calendars.join("\n");
    $("evidence-drand").checked=e.settings.drand;$("evidence-devices").checked=e.settings.devices;
    $("evidence-gateway").checked=e.settings.gateway;
    if(e.settings.drand||e.settings.devices||e.settings.gateway)$("evidence-more").open=true;
    formControls?.loaded("evidence-form");
  }
  state.evidenceGateway=e.gateway;renderGateway(e);
  $("evidence-anchor").disabled=!e.settings.enabled||e.busy;
  renderHealthDetail(status,e.health,timestampsLead(e.health),timestampsFacts(e,e.health));
}
$("evidence-form").addEventListener("input",()=>{state.evidenceDirty=true;});
$("evidence-form").addEventListener("submit",event=>{event.preventDefault();busy(event.submitter,async()=>{
  const draft=formControls?.capture("evidence-form");
  const lines=id=>$(id).value.split("\n").map(v=>v.trim()).filter(Boolean);
  const e=await json("evidence",{enabled:$("evidence-enabled").checked,interval_minutes:Number($("evidence-interval").value),
    tsa_urls:lines("evidence-tsa"),ots_calendars:lines("evidence-ots"),
    drand:$("evidence-drand").checked,devices:$("evidence-devices").checked,gateway:$("evidence-gateway").checked});
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
  if(state.view!=='witness'&&!(state.view==='settings'&&$('replica-form').closest('#view-settings')))return;
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
    $("replica-mode").value=s.retention_mode;$("replica-evidence").checked=!!s.evidence;
    $("replica-recipient").value=s.recipient_public_key||"";formControls?.loaded("replica-form");
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
    evidence:$("replica-evidence").checked,recipient_public_key:$("replica-recipient").value.trim(),
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
  if(state.view!=='witness'&&!(state.view==='settings'&&$('alerts-form').closest('#view-settings')))return;
  const form=$("alerts-form"),status=$("alerts-status");
  form.querySelectorAll("input,select,textarea,button").forEach(n=>n.disabled=!a);
  extraBadge("alerts",!!a?.settings.enabled,"On","Off");
  if(!a){status.textContent=tr("Notifications work in a real workspace, not in the demo.");return;}
  if(state.alertsProfile!==state.profile){state.alertsDirty=false;state.alertsProfile=state.profile;}
  const s=a.settings;
  if(!state.alertsDirty){
    $("alerts-enabled").checked=s.enabled;$("alerts-problems").checked=s.problems;$("alerts-changes").checked=s.changes;
    $("alerts-text").checked=!!s.include_text;$("alerts-completions").checked=!!s.completions;
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
    daily:$("alerts-daily").checked,daily_hour:Number($("alerts-hour").value),language:LANG,include_text:$("alerts-text").checked,completions:$("alerts-completions").checked,urls,add_urls:add});
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
  if(!(await askConfirm(tr("Remove every saved destination and turn notifications off?"),{danger:true})))return;
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
  state.scopeDirty=true;renderScope();$("scope-form").requestSubmit($("scope-form").querySelector("button[type=submit]"));
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
  if(widening&&!(await askConfirm(wideWarning()+"\n\n"+tr("Continue only with a dedicated account. Your confirmation is recorded in the signed journal."),{danger:true})))return;
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
  if(modesUI?.lockedExtra(name))name=null;
  state.extra=name;
  window.TgWitnessServices?.select();
  window.TgWitnessIndependentCapture?.select();
  show("extras-overview",!name);
  for(const key of ["setup","alerts","evidence","cloud","bot","github","storage","capture"]){
    show("extras-"+key,key===name);
    $("extras-open-"+key).setAttribute("aria-expanded",String(key===name));
  }
  if(name==="cloud")loadCloud().catch(error=>{if(!(error instanceof StaleView))toast(error.message,true);});
  if(name==="setup")loadSetup().catch(error=>{if(!(error instanceof StaleView))toast(error.message,true);});
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
function goPlace(place){
  const [view,part]=place.split(":");
  if(view==="setup"){nextSetupStep();return;}
  if(view==="extras"){
    navigate("witness");selectExtra(part||null);
    if(part&&state.extra===part){const heading=$("extras-"+part+"-title");heading.focus({preventScroll:true});heading.scrollIntoView({block:"start"});}
  }else if(view==="sources"){
    navigate("sources");$({capture:"capture-form",recheck:"recheck-form"}[part])?.scrollIntoView({block:"start"});
  }else if(view==="exports"){
    navigate("evidence");if(part==="settings")exportsReady.then(view=>{view.select("settings");$("report-form").scrollIntoView({block:"start"});});
  }else if(view==="connection"){
    navigate("connection");if(!state.status?.demo){connectionSettings(true);$("network-details").open=true;$("connection-options").scrollIntoView({block:"start"});}
  }else navigate(view);
}
function extraBadge(name,on,onText,offText){
  const badge=$("extra-"+name+"-badge");badge.textContent=tr(on?onText:offText);badge.classList.toggle("on",on);
}
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
  const owner=state.workspaceRevision+":"+state.profile;
  if(state.assuranceOwner!==owner&&state.status){
    const statement=state.status.assurance?await json("assurance").then(r=>r.statement,()=>null):null;
    if(owner!==state.workspaceRevision+":"+state.profile)return;
    state.assurance=statement;state.assuranceOwner=owner;
  }
  const s=state.assuranceOwner===owner?state.assurance:null,on=!!s;
  if(state.view!=='witness')return;
  show("alerts-host",on);show("cloud-active",on);
  if(!on){$("extra-cloud-badge").className="extra-badge";extraBadge("cloud",false,"","Off");renderServerHealth(null);return;}
  $("cloud-active").textContent=tr("This collector runs on a sealed {provider} server, signing key {fingerprint}. An opened SSH port or a login there is recorded in the journal and sent as a problem notification.",
    {provider:CLOUD[s.host?.mode]?.[0]||s.host?.mode||"",fingerprint:s.fingerprint});
  const profile=state.profile,h=await json("health");
  if(profile===state.profile)renderServerHealth(h.server);
}
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
  row.append(list,node("p","hint",tr("A running SSH process or an open port shows the service state; logins appear in the server's own records.")),
    node("p","hint",tr("Measured by the collector on its own host; compare with the provider's records.")));
  box.append(row);
}
async function loadExtras(){
  window.TgWitnessServices?.load();
  window.TgWitnessIndependentCapture?.select();
  await Promise.all([loadWitness(),loadAlerts(),loadEvidence(),loadReplica(),loadAssurance(),loadSourceCheck(),loadSetup(),modesUI?.refresh()]);
}

let setupView=null;
const setupReady=import("./views/setup.js?v=4").then(({createSetup,renderScales})=>{
  setupView=createSetup({root:$("extras-setup"),tr,json,node,toast,may,fmtFull,getState:()=>state,
    answered:()=>{if(state.status)state.status.setup_answered=true;renderSetupStart();renderSetupCard();},
    openExtra:name=>selectExtra(name)});
  setupView.renderScales=renderScales;
  return setupView;
}).catch(error=>{toast(error.message,true);throw error;});
async function loadSetup(){
  if(!state.status||state.status.demo||!may("settings"))return;
  const view=await setupReady,profile=state.profile;
  await view.load();
  if(profile===state.profile)renderSetupCard();
}
function renderSetupCard(){
  const data=setupView?.data;if(!data||state.view!=="witness")return;
  const goal=data.saved&&!data.saved.skipped?data.saved.goal:null,badge=$("extra-setup-badge");
  const wide=["folder","account"].includes(state.status?.scope?.mode);
  badge.textContent=goal?setupView.goalName(goal):wide?tr("No goal chosen · set up like {goal}",{goal:setupView.goalName("investigation")}):tr("No goal chosen");
  badge.classList.toggle("on",!!goal);
  setupView.renderScales($("setup-overview-scales"),data,{tr,node,compact:true});
}
function renderSetupStart(){
  const s=state.status;if(viewHost?.active!=='start')return;
  show("setup-start",!!s&&!s.demo&&!s.chats_limited&&!s.setup_answered&&may("settings"));
}
document.querySelectorAll("[data-setup-goal]").forEach(button=>button.addEventListener("click",async()=>{
  const view=await setupReady;view.start(button.dataset.setupGoal);
  navigate("witness");selectExtra("setup");
  const heading=$("extras-setup-title");heading.focus({preventScroll:true});heading.scrollIntoView({block:"start"});
}));
$("setup-start-skip").addEventListener("click",ev=>busy(ev.currentTarget,async()=>{
  await json("setup/skip",{});state.status.setup_answered=true;renderSetupStart();
}));

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
  aws:["Amazon EC2","t3.small","eu-central-1"],phala:["Phala Cloud (Intel TDX)","tdx.small","any"],
  generic:["Any server (self-attested)","",""]};
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
      "--fingerprint","COLLECTOR_FINGERPRINT",
      ...(provider==="phala"?["--cloud-init","deployments/"+name+"/docker-compose.yaml"]:[])])].join("\n");
}
$("cloud-form").addEventListener("input",renderCloud);
$("cloud-form").addEventListener("submit",e=>e.preventDefault());
renderCloud();
$("cloud-copy").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  await navigator.clipboard.writeText($("cloud-commands").textContent);toast(tr("Commands copied."));
}));

const cloudWizard={status:null,offer:null,name:"",timer:null};
const CLOUD_STAGES={
  deploy:{rank:{start:0,version:1,tunnel:2,gateway:2,server:3,running:4,waiting:4,attestation:5,done:5},rows:{
    hetzner:[[1,"Version on GitHub","A few seconds"],[2,"Cloudflare tunnel and address","A few seconds"],
      [3,"Hetzner firewall and server","Usually under a minute"],
      [4,"TgWitness installs itself on the server","Usually several minutes; the panel waits up to 30"],
      [5,"The server answers with its signing key",""]],
    phala:[[1,"Version on GitHub","A few seconds"],[2,"Cloudflare tunnel and address","A few seconds"],
      [3,"Phala Cloud confidential virtual machine","Usually a few minutes"],
      [4,"TgWitness installs itself in the confidential virtual machine","Usually several minutes; the panel waits up to 40"],
      [5,"The server answers with its signing key and Intel's attestation",""]]}},
  destroy:{rank:{start:0,server:1,tunnel:2,note:2,done:3},rows:{
    hetzner:[[1,"Hetzner server and firewall",""],[2,"Cloudflare address and tunnel",""],[3,"Done",""]],
    phala:[[1,"Phala Cloud confidential virtual machine",""],[2,"Cloudflare address and tunnel",""],[3,"Done",""]]}}};
const cloudHost=()=>viewQuery("witness",'input[name="cloud-host"]:checked')?.value||"hetzner";
function showCloudHost(host){
  const choice=viewQuery("witness",'input[name="cloud-host"][value="'+host+'"]');if(choice)choice.checked=true;
  viewQueries("witness","#cloud-wizard [data-cloud-host]").forEach(el=>{el.hidden=el.dataset.cloudHost!==host;});
}
function cloudTokens(){
  const host=cloudHost(),domain=$("cloud-cloudflare-token").value.trim();
  const gateway=host==="hetzner"?$("cloud-gateway-token").value.trim():"";
  if(domain&&gateway&&domain!==gateway)throw new Error(tr("Paste the same Cloudflare token in both fields."));
  return {provider:host,hetzner_token:host==="hetzner"?$("cloud-hetzner-token").value.trim():"",
    phala_token:host==="phala"?$("cloud-phala-token").value.trim():"",cloudflare_token:domain||gateway};
}
const cloudFailure=error=>new Error(tr(error.message)+(error.technical?" "+tr("Details: {text}",{text:error.technical}):""));
function cloudRandomName(){
  const bytes=crypto.getRandomValues(new Uint8Array(3));
  return "tgw-"+[...bytes].map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function loadCloud(){
  if(!state.me?.admin){show("cloud-wizard",false);show("cloud-remote",false);show("cloud-servers",false);return;}
  const r=await json("cloud",undefined,{root:true});
  cloudWizard.status=r;renderCloudWizard();
}
function renderCloudWizard(){
  const r=cloudWizard.status;if(!r||state.extra!=="cloud")return;
  show("cloud-remote",!r.local);show("cloud-wizard",r.local);
  renderCloudJob(r.job);renderCloudServers(r.deployments||[],r.local);
  clearTimeout(cloudWizard.timer);
  if(r.job?.state==="running")cloudWizard.timer=setTimeout(()=>{
    if(state.view==="witness"&&state.extra==="cloud")loadCloud().catch(error=>{if(!(error instanceof StaleView))toast(error.message,true);});
  },3000);
}
function cloudRow(list,label,value){
  const dd=node("dd");if(value instanceof Node)dd.append(value);else dd.textContent=value;
  list.append(node("dt","",label),dd);return dd;
}
function renderCloudOffer(){
  const o=cloudWizard.offer,s=o.server,list=$("cloud-summary");list.replaceChildren();
  const domains=[new Option(tr("Random address on trycloudflare.com"),"quick"),...o.domains.map((d,i)=>new Option(d.name,String(i)))];
  cloudRow(list,tr("Server"),tr("{type} · {cores} vCPU · {memory} GB memory · {disk} GB disk",
    {type:s.name,cores:s.cores,memory:s.memory,disk:s.disk}));
  const phala=o.provider==="phala";
  cloudRow(list,tr("Location"),phala?tr("Phala Cloud chooses the data centre; the deployment record names it")
    :[o.location.city,o.location.country].filter(Boolean).join(", ")+" ("+o.location.name+")");
  cloudRow(list,tr("Price"),phala?tr("Approximately {price} {currency} a month ({hourly} {currency} an hour), billed by Phala Cloud",
    {price:s.monthly,hourly:s.hourly,currency:o.currency})
    :tr("{price} {currency} a month including VAT, billed by Hetzner",{price:s.monthly,currency:o.currency}));
  cloudRow(list,tr("Panel address"),"").id="cloud-address";
  cloudRow(list,tr("Version"),"").id="cloud-version";
  cloudRow(list,tr("Access"),"").id="cloud-access";
  cloudRow(list,tr("DNS"),"").id="cloud-dns";
  $("cloud-gateway-account").replaceChildren(...(o.gateway_accounts||[]).map(a=>new Option(a.name||a.id,a.id)));
  $("cloud-domain").replaceChildren(...domains);$("cloud-domain").value=o.domains.length?"0":"quick";
  show("cloud-domain-field",o.domains.length>0);$("cloud-consent").checked=false;updateCloudOffer();
}
const cloudDomain=()=>cloudWizard.offer.domains[$("cloud-domain").value]||null;
function updateCloudOffer(){
  const o=cloudWizard.offer;if(!o)return;
  const domain=cloudDomain(),ref=$("cloud-wizard-ref").value.trim();
  $("cloud-address").textContent=domain?"https://"+($("cloud-wizard-name").value.trim()||cloudWizard.name)+"."+domain.name
    :tr("https://….trycloudflare.com · random; known once the server answers");
  $("cloud-access").textContent=o.provider==="phala"?tr(domain?"Intel TDX confidential virtual machine without SSH or open ports; the panel is reached only through your Cloudflare Tunnel."
    :"Intel TDX confidential virtual machine without SSH or open ports; the panel is reached only through a Cloudflare quick tunnel.")
    :tr(domain?"No SSH and no open ports; the panel is reached only through your Cloudflare Tunnel."
    :"No SSH and no open ports; the panel is reached only through a Cloudflare quick tunnel.");
  const accounts=o.gateway_accounts||[],chosen=accounts.find(a=>a.id===(domain?.account||$("cloud-gateway-account").value));
  show("cloud-gateway-field",o.gateway&&!domain&&accounts.length>1);
  $("cloud-dns").textContent=o.provider==="phala"?tr("Phala Cloud's resolvers; nobody you can ask keeps a log"):
    !o.gateway?tr("Hetzner's resolvers; nobody you can ask keeps a log"):
    chosen?.locations?tr("Only through Cloudflare Gateway, account {account}: its DNS location, shared, holds this server's lookups apart by its address. The Hetzner firewall blocks any other DNS.",{account:chosen.name||chosen.id}):
    tr("Only through Cloudflare Gateway, account {account}: a DNS location of its own. The Hetzner firewall blocks any other DNS.",{account:chosen?.name||chosen?.id||""});
  $("cloud-version").textContent=ref?tr("{ref} · looked up when the task starts",{ref})
    :tr("{ref} · commit {commit}",{ref:o.version.ref,commit:o.version.commit.slice(0,12)});
}
["cloud-domain","cloud-wizard-name","cloud-wizard-ref","cloud-gateway-account"].forEach(id=>$(id).addEventListener("input",updateCloudOffer));
$("cloud-gateway-on").addEventListener("change",()=>show("cloud-offer",false));
viewQueries("witness",'input[name="cloud-host"]').forEach(input=>input.addEventListener("change",()=>{
  showCloudHost(cloudHost());show("cloud-offer",false);
}));
$("cloud-setup").addEventListener("input",event=>{if(event.target.type!=="checkbox")show("cloud-offer",false);});
$("cloud-setup").addEventListener("submit",event=>{event.preventDefault();busy($("cloud-check"),async()=>{
  const region=document.querySelector('input[name="cloud-region"]:checked').value;
  const gateway=cloudHost()==="hetzner"&&$("cloud-gateway-on").checked;
  const r=await json("cloud/check",{...cloudTokens(),region,gateway},{root:true});
  if(r.error)throw cloudFailure(r.error);
  cloudWizard.offer={...r,region,gateway};cloudWizard.name=cloudRandomName();
  renderCloudOffer();show("cloud-offer",true);$("cloud-offer").scrollIntoView({block:"start"});
});});
$("cloud-offer").addEventListener("submit",event=>{event.preventDefault();busy($("cloud-create"),async()=>{
  const o=cloudWizard.offer,domain=cloudDomain();
  const r=await json("cloud/deploy",{...cloudTokens(),region:o.region,zone:domain?.name||"",account:domain?.account||"",
    gateway:o.gateway,gateway_account:o.gateway?(domain?.account||$("cloud-gateway-account").value):"",
    location:o.location.name,server_type:o.server.name,name:$("cloud-wizard-name").value.trim()||cloudWizard.name,
    ref:$("cloud-wizard-ref").value.trim()||null},{root:true});
  if(r.error)throw cloudFailure(r.error);
  cloudWizard.status={...cloudWizard.status,...r};show("cloud-offer",false);renderCloudWizard();
  $("cloud-job").scrollIntoView({block:"start"});
});});
function cloudElapsed(job){
  const seconds=Math.max(0,Math.round(((job.finished_at?Date.parse(job.finished_at):Date.now())-Date.parse(job.started_at))/1000));
  return Math.floor(seconds/60)+":"+String(seconds%60).padStart(2,"0");
}
function renderCloudJob(job){
  show("cloud-job",!!job);if(!job)return;
  const deploy=job.kind==="deploy",running=job.state==="running",plan=CLOUD_STAGES[job.kind];
  const phala=job.provider==="phala",rows=plan.rows[phala?"phala":"hetzner"];
  $("cloud-job-title").textContent=tr(deploy?{running:"Creating the server",done:"The server is ready",failed:"The server was not created"}[job.state]
    :{running:"Deleting the server",done:"The server is deleted",failed:"The server was not fully deleted"}[job.state]);
  $("cloud-job-lead").textContent=running?tr("Keep TgWitness running on this computer until the end. Closing this tab does not stop the task."):
    tr("Server {name}",{name:job.name});
  const reached=job.state==="done"?Infinity:plan.rank[job.stage]??0,list=$("cloud-stages");list.replaceChildren();
  let marked=false;
  for(const [rank,title,timing] of rows){
    const done=reached>rank,current=!done&&!marked;if(current)marked=true;
    const item=node("li",done?"done":current?(job.state==="failed"?"failed":"current"):""),mark=node("span");
    if(done)mark.append(icon("check"));else if(current&&job.state==="failed")mark.append(icon("x"));
    const text=node("span","",tr(title));if(timing&&!done)text.append(node("small","",tr(timing)));
    item.append(mark,text);list.append(item);
  }
  $("cloud-elapsed").textContent=tr("Elapsed: {time}",{time:cloudElapsed(job)});
  $("cloud-log").textContent=job.lines.map(line=>fmtTime(line.at)+"  "+line.text).join("\n");
  const box=$("cloud-outcome");box.replaceChildren();
  if(job.state==="failed"){
    const problem=node("div","notice error");problem.setAttribute("role","alert");
    problem.append(node("span","",tr(job.error.message)));box.append(problem);
    if(job.error.technical)box.append(node("p","hint",tr("Details: {text}",{text:job.error.technical})));
    if(deploy){
      box.append(node("p","hint",tr(phala?"Anything created before the failure is listed under Your servers. Delete it there so Phala Cloud stops billing it."
        :"Anything created before the failure is listed under Your servers. Delete it there so Hetzner stops billing it.")));
    }
  }else if(job.state==="done"&&deploy)renderCloudResult(box,job.result);
  else if(job.state==="done")box.append(node("p","notice",tr(phala?"Phala Cloud stops billing the deleted confidential virtual machine. Its record stays under Your servers."
    :"Hetzner stops billing the deleted server. Its record stays under Your servers.")));
}
function cloudFileButton(name,file,label){
  const button=node("button","quiet",tr(label));button.type="button";
  button.addEventListener("click",()=>busy(button,()=>download("cloud/deployments/"+encodeURIComponent(name)+"/"+file,name+"-"+file,false,true)));
  return button;
}
function cloudTokenButton(name,box){
  const button=node("button","secondary",tr("Show the panel token"));button.type="button";
  button.addEventListener("click",()=>busy(button,async()=>{
    const token=(await (await api("cloud/deployments/"+encodeURIComponent(name)+"/panel-token.txt",undefined,{root:true})).text()).trim();
    const code=node("code","",token),copy=node("button","quiet",tr("Copy"));copy.type="button";
    copy.addEventListener("click",()=>busy(copy,async()=>{await navigator.clipboard.writeText(token);toast(tr("Copied."));}));
    const line=node("div","cloud-actions");line.append(code,copy);button.replaceWith(line);
  }));
  box.append(button);
}
function renderCloudResult(box,result){
  const ready=node("p","notice",tr("Your TgWitness server is running. Open its panel and sign in with the panel token."));
  const link=node("a","text-link",result.panel+" ↗");link.href=result.panel;link.target="_blank";link.rel="noopener noreferrer";
  box.append(ready,link);
  if(result.quick)box.append(node("p","hint",tr("This address changes whenever the server restarts. Find the current one under Your servers.")));
  cloudTokenButton(result.name,box);
  const key=node("p","hint",tr("Signing key fingerprint: {fingerprint}. Keep a copy somewhere else: it identifies this server's evidence.",{fingerprint:result.fingerprint}));
  const steps=node("ol","cloud-howto");
  for(const text of ["Open the panel address and sign in with the panel token.","Connect a Telegram account in the server's panel.","Choose the chats to observe."])
    steps.append(node("li","",tr(text)));
  const actions=node("div","cloud-actions");actions.append(cloudFileButton(result.name,"deployment.json","Save the deployment record"));
  if(result.provider==="phala"){
    actions.append(cloudFileButton(result.name,"docker-compose.yaml","Save the measured docker-compose file"));
    box.append(key,node("p","hint",tr(result.attestation_status==="verified"?
      "Intel's attestation matched this deployment. Give a verifier the deployment record and the measured docker-compose file: python -m tgwitness.cloud verify checks the attestation against Intel's own certificates.":
      "Intel TDX verification is incomplete or needs review. Verify this deployment before relying on its attestation.")),steps,actions);
    return;
  }
  box.append(key,steps,actions);
}
const CLOUD_STATES={running:"Up and running",removed:"Server deleted",starting:"Starting"};
function renderCloudServers(list,local){
  show("cloud-servers",list.length>0);const box=$("cloud-server-list");box.replaceChildren();
  const busyJob=cloudWizard.status?.job?.state==="running";
  for(const d of [...list].reverse()){
    const row=node("div","cloud-server"),phase=d.state||"";
    const label=CLOUD_STATES[phase]?tr(CLOUD_STATES[phase]):phase.startsWith("failed")?tr("Failed: resources may remain")
      :phase.startsWith("removal failed")?tr("Deletion failed: resources may remain"):tr("Waiting for the server");
    row.append(node("h3","",d.name+" · "+label),
      node("p","",[d.panel_host?"https://"+d.panel_host:"",[d.server_type,d.location].filter(Boolean).join(" · "),d.ipv4||"",
        d.created_at?fmtFull(d.created_at):""].filter(Boolean).join(" · ")));
    if(d.quick&&d.address&&phase!=="removed")row.append(cloudAddressLink(d.address));
    if(d.attested)row.append(node("p","",tr("Intel TDX confidential virtual machine at Phala Cloud: Intel's attestation shows which code runs")));
    else if(d.provider==="phala")row.append(node("p","hint",tr("Intel TDX verification is incomplete or needs review. Verify this deployment before relying on its attestation.")));
    if(d.price&&phase!=="removed")row.append(node("p","",tr("Approximately {price} {currency} a month ({hourly} {currency} an hour), billed by Phala Cloud",
      {price:d.price.monthly,hourly:d.price.hourly,currency:d.price.currency})));
    if(d.gateway)row.append(node("p","",tr("DNS only through Cloudflare Gateway")));
    if(d.fingerprint)row.append(node("p","",tr("Signing key fingerprint: {fingerprint}",{fingerprint:d.fingerprint})));
    const actions=node("div","cloud-actions");
    if(local){
      if(d.quick&&phase!=="removed")actions.append(cloudFindButton(d.name,row));
      if(phase!=="removed")cloudTokenButton(d.name,actions);
      actions.append(cloudFileButton(d.name,"deployment.json","Save the deployment record"));
      if(phase!=="removed"&&["hetzner","phala","generic"].includes(d.provider)){
        const remove=node("button","danger",tr("Delete the server"));remove.type="button";remove.disabled=busyJob;
        remove.addEventListener("click",()=>busy(remove,()=>cloudDestroy(d.name,d.quick,d.provider)));actions.append(remove);
      }
    }
    row.append(actions);box.append(row);
  }
}
function cloudAddressLink(address){
  const link=node("a","text-link cloud-address","https://"+address+" ↗");
  link.href="https://"+address;link.target="_blank";link.rel="noopener noreferrer";return link;
}
function cloudFindButton(name,row){
  const button=node("button","secondary",tr("Find the current address"));button.type="button";
  button.addEventListener("click",()=>busy(button,async()=>{
    const r=await json("cloud/address",{name},{root:true});
    if(r.error)throw cloudFailure(r.error);
    const link=cloudAddressLink(r.address),old=row.querySelector(".cloud-address");
    if(old)old.replaceWith(link);else row.querySelector("h3").after(link);
  }));
  return button;
}
async function cloudDestroy(name,quick,provider){
  if(provider==="phala"&&cloudHost()!=="phala")showCloudHost("phala");
  if(provider==="hetzner"&&cloudHost()!=="hetzner")showCloudHost("hetzner");
  const tokens=cloudTokens(),phala=provider==="phala",key=phala?tokens.phala_token:tokens.hetzner_token;
  if(!key||(!quick&&!tokens.cloudflare_token)){
    if(!quick)$("cloud-own-domain").open=true;$(phala?"cloud-phala-token":"cloud-hetzner-token").focus();
    throw new Error(tr(phala?(quick?"Enter the Phala Cloud API key in step 2 first.":"Enter the Phala Cloud API key and the Cloudflare token in step 2 first.")
      :quick?"Enter the Hetzner token in step 2 first.":"Enter the Hetzner and Cloudflare tokens in step 2 first."));
  }
  const typed=await askText(tr("Deleting {name} removes the server with its journal and signing key for good. Export the evidence from its panel first. Type the server name to delete it:",{name}),{title:tr("Delete"),placeholder:name,maxLength:300});
  if(typed===null)return;
  const r=await json("cloud/destroy",{...tokens,name,confirm:typed.trim()},{root:true});
  if(r.error)throw cloudFailure(r.error);
  cloudWizard.status={...cloudWizard.status,...r};renderCloudWizard();$("cloud-job").scrollIntoView({block:"start"});
}
window.addEventListener("tgwitness:lock",()=>{
  clearTimeout(cloudWizard.timer);Object.assign(cloudWizard,{status:null,offer:null,name:""});
  $("cloud-setup").reset();$("cloud-offer").reset();showCloudHost("hetzner");show("cloud-offer",false);show("cloud-job",false);
});
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
      if(!(await askConfirm(tr("Revoke the token of \"{name}\"? That witness can no longer check this journal.",{name:t.label}),{danger:true,confirmText:tr("Revoke")})))return;
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
  const address=$("witness-address").value.trim(),channel=$("witness-channel").value.trim(),discord=$('witness-publisher').value==='discord';
  const validAddress=value=>{try{const u=new URL(value);return ["https:","http:"].includes(u.protocol)&&!u.username&&!u.password&&!u.search&&!u.hash;}catch{return false;}};
  if(!validAddress(address)||!validAddress($("witness-bot-api").value.trim()))throw new Error(tr("Use HTTP(S) addresses without credentials, query or fragment."));
  if(!discord&&!/^@[A-Za-z0-9_]{5,32}$|^-?\d{1,20}$/.test(channel))throw new Error(tr("Use a Telegram @channel or numeric chat ID."));
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
  if(discord){delete config.bot_token_file;delete config.channel;delete config.bot_api;config.discord_webhook_file='discord-webhook.txt';}
  saveBlob(new Blob([JSON.stringify(config,null,2)+"\n"],{type:"application/json"}),"witness.json");
  $("witness-setup-result").textContent=tr("Configuration saved. Step 3 shows how to start your witness.");
  $("witness-launch").open=true;
});});

function witnessPublisher(){
  const discord=$('witness-publisher').value==='discord';
  $('witness-channel').required=!discord;$('witness-channel').closest('label').hidden=discord;
  $('witness-bot-api').required=!discord;$('witness-discord-help').hidden=!discord;
}
$('witness-publisher').addEventListener('change',witnessPublisher);

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
  const c=v.conditions||{},box=$("verification-result"),last=Math.max(head?.seq||0,v.events);
  const stamped=!c.stamped_through?"off":c.stamped_through>=last?"ok":"part";
  const steps=[
    ["ok",tr("1. Signed journal"),tr("Records cannot be changed unnoticed after they are saved. Enough for your own use."),
      tr("Verified {n} event signatures and chain links through event #{n}.",{n:v.events})+
        (newer?" "+tr("The journal has changed since this check; verify again to check newer records."):"")+" "+
        tr("Attachments are checked when exporting a signed ZIP.")],
    [stamped,tr("2. Independent time"),tr("A third party confirms the records existed by a given time. Needed for others to accept the record."),
      (stamped==="ok"?tr("The latest timestamp receipt covers records 1–{n}.",{n:c.stamped_through})
        :stamped==="part"?tr("The latest timestamp receipt covers records 1–{n} of {total}; the next timestamped checkpoint covers the later ones.",{n:c.stamped_through,total:last})
        :c.timestamps?tr("Evidence mode is on; the next checkpoint will be timestamped.")
        :tr("Turn on: Timestamps, or a witness bot that posts to a public channel (Telegram sets the post date)."))+
      (c.witness_at?" "+tr("A witness fetched the signed journal head at {time}.",{time:fmtFull(c.witness_at)}):"")],
    ["step",tr("3. Attested collection"),tr("An attested server confirms the published code collected the records. For courts and disputes."),
      tr("Turn on: Phala server or GitHub Actions capture.")],
  ];
  const rows=[node("div","verification-group",tr("How strong is this record")),
    node("div","hint",tr("TgWitness takes no side: the same checks apply to the operator, to PhishDestroy and to anyone else. Only what a third party or the math confirms counts.")),
    ...steps.flatMap(([state,name,text,detail])=>{
      const row=node("div","verification-line "+state);
      row.append(node("strong","",({ok:"✓ ",off:"○ ",step:"→ ",part:"◐ "})[state]+name+": "),node("span","",text));
      return [row,node("div","hint",detail)];}),
    node("div","verification-line step",tr("For the recipient: the archive and your key fingerprint, sent separately."))];
  box.replaceChildren(...rows,node("div","hint",stamped==="ok"
    ?tr("With the collector fingerprint and the timestamp authority's root certificate (--tsa-ca), a recipient can meet the minimum for evidence.")
    :stamped==="part"?tr("With the collector fingerprint and the timestamp authority's root certificate (--tsa-ca), the minimum covers records 1–{n}; later records need the next timestamp.",{n:c.stamped_through})
    :c.witness_at?tr("With the collector fingerprint, the witness journal export and its public channel (--channel https://t.me/s/…), a recipient can meet the minimum when Telegram dated a witness post at the export head.")
    :tr("Integrity only: turn on Evidence mode or connect a witness bot that posts to a public channel.")));
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
  if(step==="credentials"&&state.status&&accountSignedIn()&&!window.TgWitnessAccountImport?.isEditing())step="authorized";
  show("demo-account-state",demo);
  if(demo)step="demo";
  for(const s of ["credentials","code","password"])show(s+"-form",step===s);
  show("authorized-state",step==="authorized");
  show("qr-state",step==="qr");
  show("auth-back",["code","password"].includes(step));
  $("account-heading").textContent=tr(demo?"Connect your account":step==="authorized"?"Your account":step==="credentials"?(accountState?.(state.status).needsSignIn?"Sign in again":"Add account"):"Sign in");
  const focus=step==="credentials"&&authMethod==="phone"?"phone":["code","password"].includes(step)?step:null;
  if(focus)$(focus).focus();
  window.TgWitnessAccountImport?.renderAccount();
}
function setAuthMethod(method){
  show("independent-session-option",method==="files"||method==="key");
  if(method!==authMethod){
    accountImportRevision++;importExpectedId=null;
    $("session-import-warning").open=false;
    for(const id of ["session-string","session-file","tdata-passcode","auth-key","auth-dc","auth-user-id"])$(id).value="";
    $("import-result").textContent="";
  }
  authMethod=method;
  const otherMethods=$("credentials-form").querySelector(".other-sign-in");
  if(otherMethods&&["files","key"].includes(method))otherMethods.open=true;
  panelQueries("[data-auth-method]").forEach(button=>{
    const selected=button.dataset.authMethod===method;
    button.classList.toggle("active",selected);button.setAttribute("aria-pressed",String(selected));
  });
  show("import-details",method==="files");show("auth-continue",method!=="qr");show("start-qr",method==="qr");
  show("phone-fields",method==="phone");$("phone").required=method==="phone";
  show("qr-intro",method==="qr");
  show("auth-key-fields",method==="key");
  show("session-import-warning",method==="files"||method==="key");
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
  window.TgWitnessAccountImport?.methodChanged();
  if(state.status&&$("credentials-form").isConnected)renderAccountIdentity(state.status);
}
function renderApiState(){
  const c=state.status?.collector;
  const entered=$("api-id").value&&$("api-hash").value;
  $("api-state").textContent=tr(entered?"Entered":
    c?.has_api_credentials&&!c.builtin_api?"Saved":"Built-in");
}
function apiCredentials(){
  const id=$("api-id"),hash=$("api-hash");
  const profile=importClientProfile?{client_profile:importClientProfile}:{};

  if(!id.value&&!hash.value){id.required=hash.required=false;return profile;}
  id.required=hash.required=true;
  if(!id.checkValidity()||!hash.checkValidity()||Number(id.value)<1||Number(id.value)>2147483647){
    show("api-details",true);$("api-details").open=true;
    $("api-required").firstChild.textContent=tr("Enter both API ID and API hash, or clear both fields to use the built-in pool.")+" ";
    if(!id.checkValidity()){id.reportValidity();}else if(Number(id.value)<1||Number(id.value)>2147483647){
      $("api-pair-result").textContent=tr("API ID must be between 1 and 2147483647.");id.focus();
    }else hash.reportValidity();
    return null;
  }
  return {api_id:Number(id.value),api_hash:hash.value.trim(),...profile};
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
panelQueries("[data-auth-method]").forEach(button=>button.addEventListener("click",()=>setAuthMethod(button.dataset.authMethod)));
$("api-id").addEventListener("paste",event=>{
  const text=event.clipboardData?.getData("text")||"";
  if(!text.includes(":"))return;
  event.preventDefault();
  const match=text.trim().match(/^([0-9]{1,10})\s*:\s*([a-fA-F0-9]{32})$/);
  const valid=match&&Number(match[1])>0&&Number(match[1])<=2147483647;
  $("api-pair-result").classList.toggle("error",!valid);
  if(!valid){$("api-pair-result").textContent=tr("Paste one pair: a positive API ID, a colon, and a 32-character hexadecimal API hash. Existing fields were kept.");return;}
  accountImportRevision++;importClientProfile=null;
  $("api-id").value=String(Number(match[1]));$("api-hash").value=match[2];
  $("api-pair-result").textContent=tr("Both fields filled. Telegram will validate the credentials when you sign in.");
  renderApiState();
});
for(const id of ["api-id","api-hash"])$(id).addEventListener("input",()=>{accountImportRevision++;importClientProfile=null;$("api-pair-result").textContent="";authProgress("");renderApiState();});
function clearSecrets(){
  window.TgWitnessAccountImport?.clear();
  $("panel-key-new").value="";show("panel-key-result",false);
  clearTimeout(toastTimer);show("toast",false);
  cancelQR();importExpectedId=null;importClientProfile=null;importFormats=[];importTwoFactor="";
  $("import-new-session").checked=false;accountImportRevision++;$("import-result").textContent="";
  $("session-import-warning").open=false;
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
  $("route-line-text").textContent=tr("Connection: {route}",{route:r.managed?[routeText(r),exitText(r.check)].filter(Boolean).join(" · "):
    r.kind==="direct"||(auto&&!now)?route:route+" · "+(now||r).host+":"+(now||r).port});
  show("route-line",!state.status.demo);show("network-running",!state.status.demo&&c.running);
  renderSeenBy();
  if(!$("network-pause-change")){const b=node("button","secondary small",tr("Pause observation and change the route"));b.type="button";b.id="network-pause-change";
    b.addEventListener("click",()=>busy(b,async()=>{
      if(!(await askConfirm(tr("Pause observation to change the route? New messages, edits and deletion notices are not collected while paused, and an unfinished sign-in is cancelled when the route is saved."),{confirmText:tr("Pause observation")})))return;
      await json("collector/stop",{});await refreshStatus();$("network-details").open=true;$("network-kind").focus();}));
    $("network-running").append(b);}
  $("network-pause-change").disabled=!may("collect");
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
  $("network-test").disabled=state.status.demo;
  const importedSession=!!c.account&&(c.account||{}).key_origin!=="created";
  $("sign-out").disabled=state.status.demo||importedSession;$("sign-out").hidden=importedSession;$("sign-out-locked").hidden=!importedSession;
  $("forget-session").hidden=!importedSession;$("forget-session").disabled=state.status.demo;
  const restricted=c.account_restriction&&(!c.account_restriction.until||c.account_restriction.until*1000>Date.now())?c.account_restriction:null;
  $("account-restriction").hidden=!restricted;
  if(restricted)$("account-restriction").textContent=restrictionText(restricted.kind)+" · "+(restricted.until?
    tr("sending, joining and bot buttons are off until {time}; reading continues",{time:fmtTime(new Date(restricted.until*1000).toISOString())}):
    tr("sending, joining and bot buttons are off; reading continues"));
  const pace=state.status.actions||{};
  if(!$("account-read-only").hasAttribute("aria-busy")){$("account-read-only").checked=pace.read_only!==false;
    $("account-read-only").disabled=state.status.demo||!may("account");}
  $("account-action-queue").hidden=!pace.queued;
  if(pace.queued)$("account-action-queue").textContent=tr("Queued actions: {n}. Next at {time}.",
    {n:pace.queued,time:fmtTime(new Date(pace.next_at*1000).toISOString())});
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
$("account-read-only").addEventListener("change",async()=>{const box=$("account-read-only");
  await busy(box,()=>json("interactions/read-only",{enabled:box.checked}));refreshStatus().catch(()=>{});});
document.querySelectorAll("[data-route-preset]").forEach(button=>button.addEventListener("click",()=>{
  const preset=button.dataset.routePreset;
  $("network-kind").value=preset==="auto"?"mtproxy_auto":"socks5";
  if(preset==="tor"){$("network-host").value="127.0.0.1";$("network-port").value="9050";}
  if(preset==="socks5"){$("network-host").value="";$("network-port").value="1080";}
  if(preset!=="auto"){$("network-username").value="";$("network-password").value="";}
  routeFields();
  $("route-preset-hint").textContent=preset==="tor"?tr("Tor must run on this machine: the Tor service listens on port 9050, Tor Browser on 9150. Only the main administrator can save a proxy on this machine. Save, test the connection, then choose Hide this server's address under IP protection so Telegram is never reached directly."):
    preset==="socks5"?tr("Enter the SOCKS5 address of your proxy or VPN gateway, then save and test the connection."):
    tr("Automatic MTProxy picks a working proxy from the public lists and replaces it when it fails. Save to use it.");
  (preset==="socks5"?$("network-host"):$("network-form").querySelector('[type="submit"]')).focus();
}));
const LOCAL_HOSTS=["127.0.0.1","localhost","::1"];
const RESTRICTION_NAMES={frozen:"Frozen by Telegram",spam_block:"Spam block",peer_flood:"Too many actions (PEER_FLOOD)"};
function restrictionText(kind){return RESTRICTION_NAMES[kind]?tr(RESTRICTION_NAMES[kind]):kind||"";}
function routeText(route){
  if(!route)return "";
  if(route.managed==="warp")return "Cloudflare WARP";
  if(route.managed==="vpn")return tr("WireGuard VPN");
  if(route.fallback_to_direct||route.kind==="direct")return tr("Direct connection");
  return tr({mtproxy_auto:"Automatic MTProxy",socks5:"SOCKS5 proxy",http:"HTTP proxy",mtproxy:"MTProxy"}[route.kind]||route.kind||"");
}
function countryName(code){try{return code?new Intl.DisplayNames([document.documentElement.lang||"en"],{type:"region"}).of(code):"";}catch{return code||"";}}
function exitText(check){return check&&check.exit_ip?[check.exit_ip,countryName(check.country)].filter(Boolean).join(" · "):"";}
function renderSeenBy(){
  const c=state.status.collector,r=c.network||{},id=c.client||{},list=$("seen-by-list");
  show("seen-by",!state.status.demo);if(state.status.demo)return;
  const direct=r.kind==="direct"||r.fallback_to_direct,now=r.kind==="mtproxy_auto"&&r.current,exit=exitText(r.check);
  const address=direct?tr("This server's own address")+(r.exposure==="tunnel"?" "+tr("(or that of the tunnel or VPN it uses)"):""):
    r.managed==="warp"?tr("Cloudflare WARP exit address")+(exit?": "+exit:""):
    r.managed==="vpn"?tr("Exit address of your WireGuard VPN")+(exit?": "+exit:""):
    r.kind==="socks5"&&LOCAL_HOSTS.includes(r.host)?tr("The exit of the proxy on this machine (Tor or another local proxy, port {port})",{port:r.port}):
    r.kind==="mtproxy_auto"?(now?tr("The MTProxy server {host}",{host:now.host}):tr("An MTProxy server from the public lists, once one is chosen")):
    tr("The proxy {host}",{host:r.host});
  const pair=id.api_id?"api_id "+id.api_id+" · "+tr(id.api_pair==="own application"?"own application":"built-in public pair"):
    tr("Chosen at sign-in");
  const device=[id.device_model,id.system_version,id.app_version].filter(Boolean).join(" · ");
  const rows=[[tr("Network address"),address],[tr("Application"),pair],
    [tr("Session in Telegram's device list"),device||tr("Telethon's default description of this computer")]];
  if(id.meaning)rows.push(["",tr("This public pair belongs to Telegram Desktop; the session is described as Telegram Desktop.")]);
  show("independent-session-pending",!!c.pending_new_session);
  if(c.session_origin?.method==="qr_from_import")rows.push([tr("Authorization origin"),tr("Independent QR login approved by an imported session")]);
  const checked=c.client_checks;
  const backoff=c.rpc_backoff;
  if(c.rpc_backoff_until>Date.now()/1000){
    rows.push([tr("Telegram rate limit"),backoff?.failed_method||backoff?.method||tr("Method unavailable")]);
    rows.push([tr("Requests paused until"),formatTime(new Date(c.rpc_backoff_until*1000).toISOString())]);
  }
  if(checked){
    rows.push([tr("Current authorization"),typeof checked.official_app==="boolean"?"official_app="+(checked.official_app?"True":"False"):tr("Official-app flag unavailable")]);
    rows.push([tr("Checked"),checked.checked_at||""]);
    rows.push(["",tr("The official-app flag does not report account restrictions or whether Telegram is observing the account.")]);
    for(const check of checked.checks||[])if(check.status!=="ok")rows.push([check.name,check.error||check.detail||check.status]);
  }
  for(const warning of id.warnings||[])rows.push([tr("Profile warning"),warning]);
  list.replaceChildren(...rows.flatMap(([term,value])=>[node("dt","",term),node("dd","",value)]));
}
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
  if(!(await confirmRouteChange()))return;
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
    (p.outside_route==="none"?"":p.outside_route==="direct"?
      tr("Requests outside Telegram go directly from this server."):
      tr("Requests outside Telegram go through {proxy}.",{proxy:(proxy?proxy.host+":"+proxy.port:tr("this workspace's proxy"))}));
  policyWarning();
  $("network-kind").querySelector('[value="direct"]').disabled=p.exposure!=="tunnel"&&$("network-kind").value!=="direct";
}
function policyWarning(){
  const box=$("policy-warning"),p=state.policy;if(!p)return;
  const exposure=viewQuery("connection",'input[name="exposure"]:checked')?.value||p.exposure;
  const enabled=$("outside-enabled").checked,proxy=$("outside-kind").value,route=state.status?.collector?.network?.kind;
  const blocked=enabled&&exposure==="hide"&&!proxy&&!["socks5","http"].includes(route);
  box.replaceChildren();box.hidden=!(blocked||!enabled);
  const add=(label,work)=>{const b=node("button","secondary small",label);b.type="button";b.addEventListener("click",work);box.append(b);};
  if(blocked){
    box.append(node("p","",tr("Requests outside Telegram are blocked now: timestamps, notifications, off-site copies and proxy-list updates are not sent. Hide-address mode sends them only through a SOCKS5 or HTTP proxy, and none is set.")));
    add(tr("Set a proxy for these requests"),()=>{$("outside-kind").value="socks5";policyOutsideDirty=policyFormDirty=true;outsideFields();policyWarning();$("outside-host").focus();});
    add(tr("Turn these requests off"),()=>{$("outside-enabled").checked=false;policyFormDirty=true;outsideFields();policyWarning();});
  }else if(!enabled){
    box.append(node("p","",tr("Requests outside Telegram are off: timestamps, notifications, off-site copies and proxy-list updates are not sent.")));
    add(tr("Allow requests outside Telegram"),()=>{$("outside-enabled").checked=true;policyFormDirty=true;outsideFields();policyWarning();$("outside-kind").focus();});
  }
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
for(const event of ['input','change'])$("policy-form").addEventListener(event,()=>{policyFormDirty=true;policyWarning();});
for(const id of ["outside-kind","outside-host","outside-port","outside-username","outside-password"])
  $(id).addEventListener("input",()=>{policyOutsideDirty=true;outsideFields();});
$("outside-enabled").addEventListener("change",outsideFields);
$("policy-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const owner=actionOwner(),kind=$("outside-kind").value,body={exposure:viewQuery("connection",'input[name="exposure"]:checked')?.value||"hide",
    outside_enabled:$("outside-enabled").checked,outside_proxy:null,remove_outside_proxy:false};
  if(policyOutsideDirty&&kind)body.outside_proxy={kind,host:$("outside-host").value.trim(),port:Number($("outside-port").value),
    username:$("outside-username").value,password:$("outside-password").value};
  else if(!kind&&state.policy?.outside_proxy)body.remove_outside_proxy=true;
  if(!(await askConfirm(tr("Change this workspace's IP protection and outside-request policy?"))))return;
  if(!owner.current())return;
  renderPolicy(await json("network/policy",body,{profile:owner.profile,token:owner.token}));await refreshStatus();
  toast(tr("IP protection saved."));
});});
$("network-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const kind=$("network-kind").value,body={kind},previous=state.policy;
  const exposing=kind==="direct"&&!!previous&&previous.exposure!=="tunnel";
  if(!(await (exposing?askConfirm(tr("Connect directly? Telegram will see this machine's public IP address. IP protection for this account switches to “Server behind a tunnel or VPN”. Any pending sign-in will be cancelled.")):confirmRouteChange())))return;
  if(kind!=="direct"&&kind!=="mtproxy_auto")Object.assign(body,{host:$("network-host").value.trim(),port:Number($("network-port").value)});
  if(kind==="socks5"||kind==="http")Object.assign(body,{username:$("network-username").value,password:$("network-password").value});
  if(kind==="mtproxy")body.secret=$("network-secret").value.trim();
  if(exposing){
    await json("network/policy",{exposure:"tunnel",outside_enabled:previous.outside_enabled});
    try{await json("network",body);}
    catch(error){await json("network/policy",{exposure:previous.exposure,outside_enabled:previous.outside_enabled}).catch(()=>{});throw error;}
  }else await json("network",body);
  await routeSaved();
});});
$("network-test").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  $("network-result").textContent=tr("Testing the configured Telegram route…");
  try{await json("network/test",{});$("network-result").textContent=tr("Telegram transport connected. This does not test capture completeness.");}
  catch(error){if(error instanceof StaleView)throw error;$("network-result").textContent=tr("Connection test failed. No direct fallback was attempted.");throw error;}
}));
function confirmRouteChange(){return askConfirm(tr("Change this account's connection route? Any pending sign-in will be cancelled. Saved evidence stays."));}
function renderSelectedFiles(){
  const files=[...$("session-file").files];
  $("file-picker-title").textContent=tr(files.length?"Change selected files":"Choose account files");
  $("file-picker-caption").textContent=files.length?tr("{n} selected · {size} KiB",{n:files.length,size:Math.ceil(files.reduce((sum,f)=>sum+f.size,0)/1024)}):tr("One account · up to 4 files · 8 MiB total");
  $("selected-files").textContent=files.map(f=>f.name).join(" · ");show("selected-files",!!files.length);
}
$("session-file").addEventListener("change",()=>{
  accountImportRevision++;importClientProfile=null;importFormats=[];importTwoFactor="";
  $("session-import-warning").open=!!$("session-file").files.length;
  authProgress("");
  $("session-string").value="";importExpectedId=null;
  $("import-result").textContent="";
  renderSelectedFiles();
  window.TgWitnessAccountImport?.inspect();
});
async function loadAccountFiles(){
  if(!window.TgWitnessAccountImport)throw new Error(tr("The file checker could not load. Reload the page and try again."));
  return window.TgWitnessAccountImport.read();
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
    importClientProfile=result.client_profile||null;
    importFormats=result.formats||[];importTwoFactor="";
    return result;
  }finally{if(revision===state.workspaceRevision&&selection===accountImportRevision)authProgress("");}
}
for(const id of ["auth-key","auth-dc","auth-user-id"])$(id).addEventListener("input",()=>{
  accountImportRevision++;importExpectedId=null;importClientProfile=null;importFormats=[];importTwoFactor="";$("session-string").value="";authProgress("");
  $("session-import-warning").open=!!$("auth-key").value.trim();
});
$("import-account").addEventListener("click",e=>busy(e.currentTarget,loadAccountFiles));
$("session-string").addEventListener("input",()=>{accountImportRevision++;importExpectedId=null;importClientProfile=null;importFormats=[];importTwoFactor="";$("import-result").textContent="";$("session-import-warning").open=!!$("session-string").value.trim();});
$("import-new-session").addEventListener("change",()=>{importTwoFactor="";});
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
    if(window.TgWitnessAccountImport?.adding()){await window.TgWitnessAccountImport.connectNew();return;}
    if($("session-file").files.length){
      const imported=await loadAccountFiles();if(!imported)return;
    }
    if(!$("session-string").value.trim()){
      throw new Error(tr("Choose a Telethon/Pyrogram .session file, a TData .zip, or a JSON containing authorization. You can also paste a Telethon StringSession under Passcode or session text."));
    }
  }
  const credentials=apiCredentials();if(!credentials)return;
  const selection=accountImportRevision;
  await cancelQR();
  if(revision!==state.workspaceRevision||method!==authMethod||selection!==accountImportRevision)return;
  const body=method==="phone"?{...credentials,phone:$("phone").value}:
    {...credentials,session:$("session-string").value.trim(),expected_user_id:importExpectedId};
  const independent=method!=="phone"&&$("import-new-session").checked;
  if(independent)Object.assign(body,{formats:importFormats,two_factor_password:importTwoFactor});
  let r;
  if(method==="phone"&&state.status.collector.has_api_credentials===undefined){

    await loginRequest("auth/configure",credentials,{profile});
    if(revision!==state.workspaceRevision)return;
    r=await loginRequest("auth/phone",{phone:body.phone},{profile});
  }else r=await loginRequest(method==="phone"?"auth/phone/start":independent?"auth/session/new":"auth/configure",body,{profile});
  if(revision!==state.workspaceRevision)return;
  if(r.step==="authorized")clearSecrets();
  setAuthStep(r.step);
  if(r.error)toast(tr(r.error),true);
  await refreshStatus();
});});
async function cancelQR(){
  const pending=qrPending;qrPending=null;
  if(pending)clearTimeout(pending.timer);
  $("qr-image").removeAttribute("src");show("qr-state",false);
  if(pending&&state.token){try{await json("auth/qr/"+encodeURIComponent(pending.id)+"/cancel",{},{profile:pending.profile,allowStale:true,signal:AbortSignal.timeout(10000)});}catch(_){} }
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
$("auth-back").addEventListener("click",()=>{clearSecrets();window.TgWitnessAccountImport?.edit();setAuthStep("credentials");});
$("change-account").addEventListener("click",()=>{if(state.status.collector.running){toast(tr("Pause observation before changing accounts."),true);return;}clearSecrets();window.TgWitnessAccountImport?.edit();setAuthStep("credentials");});
$("sign-out").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const owner=actionOwner();
  if(state.status.collector.running){toast(tr("Pause observation before signing out."),true);return;}
  if(!(await askConfirm(tr("Sign out of this Telegram account? TgWitness ends the session in Telegram and forgets it on this computer. The journal, sources and signing key stay; only the same account can connect to this workspace again."),{danger:true,confirmText:tr("Sign out of Telegram")})))return;
  if(!owner.current())return;
  const r=await json("auth/logout",{},{profile:owner.profile,token:owner.token});
  clearSecrets();await refreshStatus();setAuthStep("credentials");
  toast(tr(r.telegram_session_ended?"Signed out. Telegram ended the session.":
    "Signed out here. Telegram did not confirm: end the session in Telegram under Settings → Devices."),!r.telegram_session_ended);
}));
async function showAccountSessions(){
  const owner=actionOwner(),box=$("account-sessions");
  const r=await json("account/sessions",undefined,{profile:owner.profile,token:owner.token});
  if(!owner.current())return;
  box.replaceChildren();box.hidden=false;
  const others=r.sessions.filter(s=>!s.current).length;
  box.append(node("p","hint",others?tr("Other sessions signed in to this account: {n}",{n:others}):
    tr("No other sessions. Only this one is signed in.")));
  if(others){
    const all=node("button","quiet danger",tr("End all other sessions"));all.type="button";
    all.addEventListener("click",e=>busy(e.currentTarget,async()=>{
      if(!(await askConfirm(tr("End all other sessions in Telegram? Every other device signed in to this account is logged out."),{danger:true,confirmText:tr("End all other sessions")})))return;
      if(!owner.current())return;
      const done=await json("account/sessions/end-others",{},{profile:owner.profile,token:owner.token});
      toast(tr("Other sessions ended: {n}",{n:done.terminated}));await showAccountSessions();
    }));
    box.append(all);
  }
  const only=node("button","quiet danger",tr("Make this the only session"));only.type="button";
  only.addEventListener("click",e=>busy(e.currentTarget,async()=>{
    if(!(await askConfirm(tr("End every other session of this account and turn on a two-step password if it has none? After that, signing in anywhere else needs that password."),{danger:true,confirmText:tr("Make this the only session")})))return;
    if(!owner.current())return;
    const done=await json("account/sessions/only",{},{profile:owner.profile,token:owner.token});
    if(done.password)await window.TgWitnessDialogs.prompt(done.password,{title:tr("Two-step password"),label:tr("Two-step password set by TgWitness. Save it now: it is shown only once and TgWitness does not keep it."),required:false});
    toast(tr("This is now the only session of this account."));await showAccountSessions();
  }));
  box.append(only);
  for(const s of [...r.sessions].sort((a,b)=>Number(b.current)-Number(a.current)||String(b.active_at).localeCompare(String(a.active_at)))){
    const row=node("div","account-session"+(s.current?" current":""));
    row.append(node("span","account-session-device",[s.device_model,[s.app_name,s.app_version].filter(Boolean).join(" ")].filter(Boolean).join(" · ")+
      (s.official_app?"":" · "+tr("unofficial app"))));
    row.append(node("span","muted",[[s.region,s.country].filter(Boolean).join(", "),tr("first sign-in {date}",{date:(s.created_at||"").slice(0,10)}),
      s.current?"":tr("last active {date}",{date:(s.active_at||"").slice(0,10)})].filter(Boolean).join(" · ")));
    if(s.current)row.append(node("strong","",tr("This session (TgWitness)")));
    else{
      const end=node("button","quiet danger",tr("End session"));end.type="button";
      end.addEventListener("click",e=>busy(e.currentTarget,async()=>{
        if(!(await askConfirm(tr("End this session in Telegram? The device signed in there is logged out. This cannot be undone from TgWitness."),{danger:true,confirmText:tr("End session")})))return;
        if(!owner.current())return;
        await json("account/sessions/end",{hash:s.hash},{profile:owner.profile,token:owner.token});
        toast(tr("Session ended."));await showAccountSessions();
      }));
      row.append(end);
    }
    box.append(row);
  }
}
$("account-sessions-show").addEventListener("click",e=>busy(e.currentTarget,showAccountSessions));
$("account-password").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const owner=actionOwner();
  const prompt=(label,options={})=>window.TgWitnessDialogs.prompt("",{title:tr("Two-step password"),label:tr(label),maxLength:256,...options});
  const current=await prompt("Current two-step password. Leave empty if the account has none.",{type:"password",autocomplete:"current-password",required:false});
  if(current===null||!owner.current())return;
  const next=await prompt("New two-step password.",{type:"password",autocomplete:"new-password"});
  if(next===null||!owner.current())return;
  const hint=await prompt("Password hint (optional).",{required:false});
  if(hint===null||!owner.current())return;
  await json("account/password",{current_password:current||null,new_password:next,hint},{profile:owner.profile,token:owner.token});
  toast(tr("Two-step password saved in Telegram. TgWitness does not keep it."));
}));
$("forget-session").addEventListener("click",e=>busy(e.currentTarget,async()=>{
  const owner=actionOwner();
  if(state.status.collector.running){toast(tr("Pause observation before forgetting the session."),true);return;}
  if(!(await askConfirm(tr("Forget this session on this computer? It stays active in Telegram. The journal, sources and signing key stay; only the same account can connect to this workspace again."),{confirmText:tr("Forget on this computer")})))return;
  if(!owner.current())return;
  await json("auth/forget",{},{profile:owner.profile,token:owner.token});
  clearSecrets();await refreshStatus();setAuthStep("credentials");
  toast(tr("Forgotten on this computer. The session is still active in Telegram."));
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
  const m=s.monitoring||{},on=["messages","edits","deletions","reactions","membership","profiles","presence"].filter(k=>m[k]);
  return on.length===7?tr("Everything"):on.join()==="messages,edits,deletions"?tr("Messages, edits & deletions"):
    on.length?tr("Custom: {list}",{list:on.map(termText).join(", ")}):tr("Nothing selected");
}
function modeSummary(s){
  const free=s.collector?.disk_free_bytes,files=s.capture?.download_media?tr("attachments: {list}",{list:mediaLimitText(s.capture)})
    +(free?" · "+tr("{size} free on disk",{size:humanSize(free)}):""):tr("photos & files not saved");
  return tr("Mode: {mode}",{mode:recordingMode(s)})+" · "+files;
}
async function openRecordingSettings(){
  await navigate("sources");sourcesView?.showTab('recording');$("capture-form").scrollIntoView({block:"start"});
}
const exportRunning=()=>multiRunning()&&state.multi.chat_id===state.chat||state.status?.collector.chat_export?.phase==="running";
let chatListRequest=0;
async function refreshChats(refresh=false,wanted=null){
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
  if(wanted!==null&&state.chat!==wanted&&state.chats.some(c=>c.chat_id===wanted)){beginChat(wanted);refresh=false;}
  if(state.chat!==null&&!state.chats.some(c=>c.chat_id===state.chat))beginChat(null);
  if(state.chat===null&&state.chats.length){beginChat((state.chats.find(c=>c.enabled)||state.chats[0]).chat_id);refresh=false;}
  renderChatsList();
  if(state.chat===null){renderChatEmpty();return;}
  return await loadChatMessages(refresh?"refresh":"open");
}
let chatListView=null;
const chatListReady=import('./views/chat-list.js?v=layout1').then(({createChatList})=>{
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
  $("chat-history-feedback")?.remove();
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
  if(state.chat!==null&&!state.chats.some(c=>c.chat_id===state.chat)&&(state.chatsLoading||!state.chats.length)){box.append(viewState('loading',tr('Loading…')));return;}
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
  $("chat-avatar").replaceWith(avatar);$("chat-name").textContent=title;$("chat-name").title=title;
  const kind={supergroup:tr("Group"),megagroup:tr("Group"),group:tr("Group"),chat:tr("Group"),channel:tr("Channel"),broadcast:tr("Channel"),bot:tr("Bot"),user:tr("Private chat"),private:tr("Private chat")}[info.kind]||termText(info.kind);
  const split=typeof info.deleted_saved==="number";
  $("chat-sub").textContent=$("chat-sub").title=[kind,tr("{n} saved",{n:(split?info.saved:info.messages||0).toLocaleString()}),
    split?(info.deleted_saved?tr("{n} deleted, text kept",{n:info.deleted_saved}):""):(info.deleted?tr("{n} deleted",{n:info.deleted}):""),
    split&&info.deleted_unsaved?tr("{n} deleted before saving",{n:info.deleted_unsaved}):"",
    info.missing?tr("{n} not found on recheck",{n:info.missing}):"",info.edited?tr("{n} edited",{n:info.edited}):""].filter(Boolean).join(" · ");
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
  for(const [name,label] of [['mode',tr("Mode: {mode}",{mode:recordingMode(s)})],['files',s.capture?.download_media?mediaLimitText(s.capture,true):tr("Files off")]]){
    const allowed=!s.demo&&viewAllowed('sources'),chip=node(allowed?'button':'span','chat-setting-chip',label);chip.dataset.recording=name;chip.title=label+' · '+modeSummary(s);
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
  const views=[['messages',tr('Messages')],['people',tr('People')],['activity',tr('Activity timeline')],['profile',tr('Profile')]];
  if(s.analysis?.enabled&&!s.demo&&viewAllowed('analysis'))views.push(['ai',tr('AI context')]);
  for(const [name,label] of views){const tab=node('button','filter'+(state.chatView===name?' active':''),label);tab.type='button';tab.dataset.chatView=name;
    tab.setAttribute('aria-pressed',String(state.chatView===name));tab.addEventListener('click',()=>{
      if(name==='ai'){busy(tab,async()=>{const chat=state.chat,revision=state.workspaceRevision;await navigate('analysis');
        if(revision===state.workspaceRevision)await window.TgWitnessAnalysis?.focusChat(chat);});return;}
      state.chatView=name;renderChatStatus();renderChatFeed();renderComposer();});tabs.append(tab);}
  const toolbar=node("details","action-menu chat-filter-row"),summary=node('summary'),filterPanel=node('div','action-menu-panel');
  summary.append(icon('settings'),node('span','',tr({all:'Filters',deleted:'Deleted',edited:'Edited',media:'Media'}[state.chatFilter]||'Filters')));
  filterPanel.append(filters);toolbar.append(summary,filterPanel);toolbar.hidden=state.chatView!=='messages';
  const recording=$('chat-recording-options');recording.replaceChildren();
  if(!s.demo){
    if(!info.enabled||!c.has_session||c.running&&(c.storage_low||!c.connected))box.append(state_);
    else recording.append(state_);
    recording.append(mode);
  }
  else {
    const hint=node("span","visually-hidden",tr("Demo with fictional messages. Deleted messages are red; edited ones keep every saved version."));
    box.append(hint);
  }
  const viewBar=node('div','chat-view-bar');viewBar.append(tabs,toolbar);box.append(viewBar);
  if(state.chatAuthor!==null&&state.chatView==='messages'){
    const who=state.chatMessages.find(m=>m.sender?.id===state.chatAuthor),chip=node("div","chat-author-chip");
    const author=who?senderName(who):"ID "+state.chatAuthor;chip.append(node("span","",tr("Showing only messages from {name}",{name:author})));
    const clear=node("button","text-link",tr("Show everyone"));clear.type="button";
    clear.addEventListener("click",()=>{state.chatAuthor=null;renderChatStatus();renderChatFeed();});chip.append(clear);box.append(chip);
  }
  const blocked=s.demo||!c.has_session||!info.enabled||c.available_for_export===false;
  $("chat-load-history").disabled=blocked;$("chat-history-limit").disabled=blocked;
  $("chat-export-start").disabled=s.demo||!c.has_session||exportRunning();
  if(focusedFilter)summary.focus({preventScroll:true});
  if(focusedView)box.querySelector('[data-chat-view="'+focusedView+'"]')?.focus({preventScroll:true});
}
let peopleTimeline;
const peopleTimelineReady=import('./views/people-timeline.js?v=1').then(({createPeopleTimeline})=>{
  peopleTimeline=createPeopleTimeline({root:$("chat-feed"),json,tr,
    owner:()=>state.workspaceRevision+':'+state.profile+':'+state.chat,
    active:()=>state.view==='chats'&&state.chatView==='activity'&&state.chat!==null,
    record:openRecord,formatTime:fmtFull});return peopleTimeline;
});
window.addEventListener('tgwitness:lock',()=>peopleTimeline?.reset());
function renderChatFeed(){
  if(state.view!=='chats')return;
  const feed=$("chat-feed"),s=state.status,info=state.chatInfo;
  if(state.chatView==='activity'){peopleTimelineReady.then(view=>view.load());return;}
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
    if(state.chatProfile?.chat!==state.chat)loadChatProfile().catch(()=>{});
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
      viewState("empty",tr("No messages saved for this chat yet"),tr(s.demo?"This demo chat has no messages.":"Load recent messages from Telegram to see the conversation. Keep observation on to catch new messages, edits and deletions."),tr("Load last 100 messages"),!s.demo&&s.collector.has_session&&info.enabled?()=>loadHistory(null,100):null);
    empty.classList.add("chat-feed-empty");
    next.push(empty);newer();placeChildren(feed,next);return;
  }
  const byId=new Map(state.chatMessages.map(m=>[m.message_id,m]));
  let lastDay=null,lastSender=null,lastTime=0;
  for(const m of shown){
    const when=m.sent_at||m.versions[0]?.observed_at||m.deleted_observed_at,day=panelTime.dayKey(when);
    if(day!==lastDay){const chip=days.get(day)||node("div","chat-day"),label=fmtDay(when);chip.dataset.day=day;
      if(chip.textContent!==label)chip.textContent=label;chip.title=label;next.push(chip);lastDay=day;lastSender=null;}
    if(m.service_action){const service=node("div","chat-service",senderName(m)+" "+serviceText(m.service_action)+" · ");service.id='msg-'+m.message_id;service.append(timeNode(when));
      const ref=m.reference;if(ref)boardView?.attach(service,{hash:ref.event_hash,seq:ref.seq,kind:ref.kind,chat_id:state.chat,message_id:m.message_id});next.push(service);lastSender=null;continue;}
    const sid=m.sender?.id??null,t=when?new Date(when).getTime():0,grouped=sid!==null&&sid===lastSender&&t>=lastTime&&t-lastTime<300000;
    lastSender=sid;lastTime=t;
    const old=oldRows.get('msg-'+m.message_id),key=JSON.stringify([chatGeneration,m,grouped,m.reply_to&&byId.get(m.reply_to),may('interact'),s.demo,s.collector.has_session,chatSafety?.key()]);
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
function messageText(value,m,className="bubble-text"){
  const profile=state.profile,revision=state.workspaceRevision,chat=state.chat,generation=chatGeneration;
  return window.TgWitnessPrivacy.render(value,{className,tr,
    current:()=>profile===state.profile&&revision===state.workspaceRevision&&chat===state.chat&&generation===chatGeneration,
    reveal:m?()=>json("privacy/reveal",{chat_id:chat,message_id:m.message_id},{profile}):null});
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
    if(target){quote.type='button';quote.append(node('b','',senderName(target)),node('span','',window.TgWitnessPrivacy.preview(target.text||tr('[attachment]'))));
      quote.addEventListener('click',()=>{let el=$('msg-'+m.reply_to);if(!el){state.chatFilter='all';state.chatAuthor=null;renderChatStatus();renderChatFeed();el=$('msg-'+m.reply_to);}if(!el)return;
        el.scrollIntoView({block:'center',behavior:'smooth'});el.classList.add('flash');setTimeout(()=>el.classList.remove('flash'),1600);});}
    else quote.textContent=tr('Reply to #{id} · outside this loaded window',{id:m.reply_to});
    bubble.append(quote);
  }
  if(m.captured){if(m.text)bubble.append(messageText(m.text,m));if(m.buttons)bubble.append(buttonsNode(m.buttons,m));}
  else bubble.append(node("div","bubble-text muted-text",tr(m.deleted?"Deleted before TgWitness could save it — only the deletion notice was recorded.":"Content was not saved.")));
  m.media.forEach(media=>bubble.append(mediaNode(media)));
  if(m.has_media&&!m.media.length){const missing=node('span','media-missing');missing.title=tr('Attachment file not saved');missing.setAttribute('role','img');missing.setAttribute('aria-label',missing.title);missing.append(icon('clip'));bubble.append(missing);}
  const meta=node("div","bubble-meta");
  if(m.deleted&&m.auto_deleted){const d=node("span","pill pill-deleted",tr("Deleted"));d.title=tr("Deletion seen {time}, when the message's auto-delete timer expired: an expected removal by the timer.",{time:fmtFull(m.deleted_observed_at)});meta.append(d);}
  else if(m.deleted){const d=node("span","pill pill-deleted",tr("Deleted"));d.title=tr("Deletion notice received {time}; the saved content stays.",{time:fmtFull(m.deleted_observed_at)});meta.append(d);}
  else if(m.missing&&m.auto_deleted){const d=node("span","pill pill-missing",tr("Not found at recheck"));d.title=tr("Telegram no longer returned this message at {time}; its auto-delete timer had expired before that check.",{time:fmtFull(m.missing_observed_at)});meta.append(d);}
  else if(m.missing){const d=node("span","pill pill-missing",tr("Not found at recheck"));d.title=tr("Telegram no longer returned this message at {time} and no deletion notice was received: deleted while notices were missed, removed by an auto-delete timer, or no longer visible to this account.",{time:fmtFull(m.missing_observed_at)});meta.append(d);}
  if(m.versions.length>1){const e=node("button","pill pill-edited",tr("Edited · {n} versions",{n:m.versions.length}));e.type="button";e.title=tr("Show every saved version");
    e.setAttribute("aria-expanded","false");
    e.addEventListener("click",()=>{const open=bubble.querySelector(".versions");e.setAttribute("aria-expanded",String(!open));if(open){open.remove();return;}bubble.insertBefore(versionsNode(m),meta);});meta.append(e);}
  else if(m.edited){const e=node("span","pill pill-edited",tr("Edited"));e.title=tr("Telegram marks this message as edited; the earlier text was not saved.");meta.append(e);}
  if(!m.origins.includes("live")&&m.origins.includes("history")){const o=node("span","origin",tr("from history"));o.title=tr("Loaded from chat history, not seen live");meta.append(o);}
  meta.append(timeNode(m.sent_at||m.versions[0]?.observed_at,"time"));
  if(chatSafety?.writable()&&!state.status?.demo&&state.status?.collector.has_session&&!m.deleted&&!m.missing&&may("interact")){const reply=node("button","text-link",tr("Reply"));reply.type="button";
    const generation=chatGeneration,revision=state.workspaceRevision;
    reply.addEventListener("click",()=>{if(!chatReady||generation!==chatGeneration||revision!==state.workspaceRevision)return;
      composeReply=m.message_id;composeOpen=true;renderComposer();$("chat-message").focus();});meta.append(reply);}
  bubble.append(meta);row.append(bubble);
  const version=m.versions.at(-1);
  const ref=version||m.reference;
  if(ref)boardView?.attach(row,{hash:ref.event_hash,seq:ref.seq,kind:ref.kind,chat_id:state.chat,message_id:m.message_id,payload:{text:version?.text||''}},version?bubble.querySelector('.bubble-text'):null);
  return row;
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
    if(p.id!==null&&may('board.write')){const slice=node('button','quiet small',tr('Slice this person’s actions'));slice.type='button';slice.addEventListener('click',event=>{event.stopPropagation();boardView?.sliceDialog({chat_id:id,actors:[p.id]});});who.append(slice);}
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
        if(!(await askConfirm(tr("Profiles are personal data about third parties. Turn them on only when you have a lawful reason, and delete them when no longer needed. Continue?"))))return;
        await json("chats/"+encodeURIComponent(chat)+"/dossier",{enabled:true});await refreshStatus();renderChatFeed();
      }));
    return bar;
  }
  const password=node("input");password.type="password";password.autocomplete="new-password";password.maxLength=256;
  password.placeholder=tr("Password for an encrypted copy (12+ characters)");password.setAttribute("aria-label",tr("Password for an encrypted copy"));password.disabled=demo;
  const encryption=node("select");encryption.setAttribute("aria-label",tr("Password encryption"));encryption.disabled=demo;
  encryption.append(new Option(tr("ZIP (7-Zip / WinRAR)"),"zip"),new Option(tr("Stronger encryption (scrypt + AES-GCM, requires verify.py to open)"),"tgwpw"));
  const encryptionHint=node("p","hint");
  const updateEncryptionHint=()=>{encryptionHint.textContent=tr(encryption.value==="tgwpw"
    ? "Open with an independently obtained verify.py: python verify.py unseal-password export.tgwpw --out output-file. Then verify the decrypted evidence."
    : "ZIP password protection uses WinZip AES (weak key stretching). Use a long random passphrase of 20+ characters, or sealed delivery for sensitive exports.");};
  encryption.addEventListener("change",updateEncryptionHint);updateEncryptionHint();
  bar.append(node("p","",tr("Profiles are on. Click a person to open their profile. The export is a separate signed file; it is deleted with the chat.")),
    action("secondary",tr("Export profiles"),async()=>{
      if(await download("chats/"+encodeURIComponent(chat)+"/dossier/export","tgwitness-dossier-"+chat+".json"))toast(tr("Signed profiles saved."));
    }),
    password,encryption,encryptionHint,
    action("quiet",tr("Export encrypted"),async()=>{
      if(password.value.length<12){password.focus();throw new Error(tr("Enter a password of at least 12 characters."));}
      if(await download("chats/"+encodeURIComponent(chat)+"/dossier/export","tgwitness-dossier-"+chat+"-encrypted."+encryption.value,false,false,{password:password.value,encryption:encryption.value}))
        toast(tr("Encrypted export sent to your browser. Keep its password separately."));
      password.value="";
    }),
    action("quiet",tr("Turn off and delete"),async()=>{
      if(!(await askConfirm(tr("Turn off profiles for this chat and delete the saved profile file?"),{danger:true})))return;
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
    const sensitive=window.TgWitnessPrivacy.enabled&&(window.TgWitnessPrivacy.ranges(v.text).length||i&&window.TgWitnessPrivacy.ranges(m.versions[i-1].text).length);
    const presentation=value=>JSON.parse(window.TgWitnessPrivacy.recordPreview(value));
    item.append(i&&!sensitive?window.TgWitnessReview.compare(presentation(m.versions[i-1]),presentation(v),tr):messageText(v.text||tr("(no text)"),m,"version-text"));
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
      item.append(node("span","label",window.TgWitnessPrivacy.preview(b.text||"—")),node("small","kind",buttonKinds[b.type]||b.type));
      if(target)item.append(node("code","target",window.TgWitnessPrivacy.preview(target)));
      if(chatSafety?.writable()&&may('interact')&&message&&!message.deleted&&!message.missing&&["callback","text"].includes(b.type)&&!state.status?.demo){
        const press=node("button","secondary small",tr("Press button"));press.type="button";
        press.disabled=actionBusy||!chatReady||!state.status?.collector.has_session||!state.chatInfo?.enabled;
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


let composeContext=null,composeReply=null,composeOpen=false,linkPreview=null,actionBusy=false;
let chatGeneration=0,chatReady=false,composeDestination=null,chatPageRequest=0,chatPagePending=null;
const chatSafety=window.TgWitnessChatSafety?.create({
  context:()=>({profile:state.profile,revision:state.workspaceRevision,chat:state.chat,account:state.status?.collector.account,
    evidence:state.status?.setup_goal==='evidence',readOnly:!!state.status?.actions?.read_only,
    allowed:!!(state.status&&!state.status.demo&&state.status.setup_goal!=='evidence'&&!state.status.actions?.read_only&&state.status.collector.has_session&&state.status.collector.account?.id!=null&&may('interact'))}),
  root:()=>panelRoots.get('chats'),tr,warn:message=>toast(message,true),
  audit:()=>json('privacy/reveal',{chat_id:state.chat,reason:'display_preference'}),
  changed:()=>{composeOpen=false;composeReply=null;renderComposer();renderChatFeed();}});
const pendingActions=new Map();
function resetInteractions(){
  chatSafety?.reset();
  $("chat-history-feedback")?.remove();
  composeContext=null;composeReply=null;composeOpen=false;linkPreview=null;
  chatGeneration++;chatReady=false;composeDestination=null;
  $("chat-message").value="";$("chat-link").value="";$("chat-link-preview").replaceChildren();
  $("chat-search").value="";
  viewQuery("chats",".chats-shell").dataset.panel="chat";
  show("interaction-result",false);show("chat-reply",false);
}
function renderComposer(){
  if(state.view!=='chats')return;
  chatSafety?.sync();
  const context=state.workspaceRevision+":"+chatGeneration+":"+state.profile+":"+state.chat;
  if(composeContext!==context){$("chat-message").value="";composeReply=null;composeContext=context;composeOpen=false;show("interaction-result",false);}
  const s=state.status,enabled=!!(chatReady&&s&&!s.demo&&s.collector.has_session&&state.chatInfo?.enabled);
  const allowed=!!(state.chatView==='messages'&&chatSafety?.writable()&&s&&!s.demo&&s.collector.has_session&&may('interact'));
  const account_=s?.collector.account,who=account_?(account_.username?"@"+account_.username:"ID "+account_.id):tr("this account");
  show("chat-compose-toggle",allowed&&!composeOpen);
  $("chat-compose-open").textContent=tr("Write as {account}",{account:who});
  $("chat-compose-open").disabled=!allowed;
  $("chat-compose-warning").textContent=tr("Chat members will see this message, and the action is recorded in the signed journal.");
  show("chat-compose",allowed&&composeOpen);
  composeDestination=enabled?{chat:state.chat,profile:state.profile,revision:state.workspaceRevision,generation:chatGeneration}:null;
  const writing=actionBusy||$("chat-send").hasAttribute("aria-busy")||!!$("chat-feed").querySelector(".msg-button button[aria-busy]");
  $("chat-send").disabled=!enabled||writing;$("chat-message").disabled=!enabled||writing;
  for(const button of $("chat-feed").querySelectorAll(".msg-button button"))button.disabled=!enabled||writing;
  $("chat-message").placeholder=tr("Write a message…");
  const account=s?.collector.account;
  const identity=account?(account.username?"@"+account.username:"ID "+account.id):tr("No account connected");
  $("chat-compose-account").textContent=tr("Sending as {account}",{account:identity});
  show("chat-reply",composeReply!==null);$("chat-reply-label").textContent=tr("Reply to message #{id}",{id:composeReply});
  $("chat-preview-button").disabled=!s||s.demo||!s.collector.has_session||writing;
}
function actionResult(result){
  const box=$("interaction-result");box.replaceChildren();show("interaction-result",true);
  const labels={succeeded:tr("Action completed and recorded."),approval_pending:tr("Join request sent. Waiting for administrator approval."),
    rejected:tr(result.error?"The action was not sent.":"Telegram did not accept the action."),
    unknown:tr("The result is unknown. Check the chat before attempting a new action."),
    queued:result.run_at?tr("Queued to keep a safe pace. Runs at {time}.",{time:fmtTime(new Date(result.run_at*1000).toISOString())}):""};
  box.append(node("strong","",labels[result.status]||result.status));
  if(result.error)box.append(node("p","",tr(result.error)));
  else if(result.error_type)box.append(node("span","",result.error_type));
  if(result.retry_after)box.append(node("p","",tr("Retry after {n} seconds.",{n:result.retry_after})));
  if(result.answer?.message)box.append(window.TgWitnessPrivacy.render(result.answer.message,{className:"bubble-text",tr}));
  if(result.answer?.url)box.append(node("code","target",window.TgWitnessPrivacy.preview(result.answer.url)));
  const seq=result.result_event||result.request_event;
  if(seq){const record=node("button","text-link",tr("Journal record #{n}",{n:seq}));record.type="button";
    record.addEventListener("click",()=>busy(record,()=>openRecord(seq)));box.append(record);}
}
async function panelAction(body,{profile=state.profile,revision=state.workspaceRevision}={}){
  if(actionBusy||profile!==state.profile||revision!==state.workspaceRevision)return null;
  if(body.action!=="open"&&(!chatReady||body.chat_id!==state.chat))return null;
  if(!await chatSafety?.confirm(body.action))return null;
  if(actionBusy||profile!==state.profile||revision!==state.workspaceRevision)return null;
  if(body.action!=="open"&&(!chatReady||body.chat_id!==state.chat))return null;
  actionBusy=true;renderComposer();
  const key=profile+":"+JSON.stringify(body);
  if(!pendingActions.has(key))pendingActions.set(key,Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,"0")).join(""));
  try{
    const result=await json("interactions",{...body,request_id:pendingActions.get(key)},{profile});
    if(revision!==state.workspaceRevision)return result;
    if(["succeeded","queued"].includes(result.status)&&body.action==="send"&&body.chat_id===state.chat){$("chat-message").value="";composeReply=null;}

    if(body.action==="open"||body.chat_id===state.chat)actionResult(result);
    if(result.status==="queued")followAction(result,body,{profile,revision});
    let refreshFailed=false;
    try{
      await refreshStatus();
      if(revision!==state.workspaceRevision)return result;
      refreshFailed=(await refreshChats(body.action!=="send"))===false;

      if(!refreshFailed&&result.status!=="unknown")pendingActions.delete(key);
    }catch{refreshFailed=true;}
    if(refreshFailed&&revision===state.workspaceRevision&&(body.action==="open"||body.chat_id===state.chat)){
      actionResult(result);$("interaction-result").append(node("p","hint",tr("The receipt is saved. Chat refresh failed; refresh the view to see the latest messages.")));
    }
    return result;
  }finally{actionBusy=false;renderComposer();}
}
async function followAction(result,body,{profile,revision}){
  const current=()=>profile===state.profile&&revision===state.workspaceRevision;
  while(result.status==="queued"){
    await new Promise(resolve=>setTimeout(resolve,Math.min(Math.max(result.run_at*1000-Date.now(),2000),15000)));
    if(!current())return;
    try{result=await json("interactions/"+encodeURIComponent(result.request_id),undefined,{profile});}catch{return;}
  }
  if(!current())return;
  if(body.action==="open"||body.chat_id===state.chat)actionResult(result);
  try{await refreshStatus();if(current())await refreshChats(body.action!=="send");}catch{}
}
$("chat-compose").addEventListener("submit",e=>{e.preventDefault();const dest=composeDestination;
  if(!dest||!chatReady||dest.generation!==chatGeneration||dest.chat!==state.chat||dest.revision!==state.workspaceRevision)return;
  busy($("chat-send"),()=>panelAction({action:"send",chat_id:dest.chat,text:$("chat-message").value,reply_to:composeReply},dest));});
$("chat-reply-cancel").addEventListener("click",()=>{composeReply=null;renderComposer();});
$("chat-compose-open").addEventListener("click",()=>{composeOpen=true;renderComposer();$("chat-message").focus();});
$("chat-compose-close").addEventListener("click",()=>{composeOpen=false;composeReply=null;renderComposer();$("chat-compose-open").focus();});
$("chat-link").addEventListener("input",()=>{linkPreview=null;$("chat-link-preview").replaceChildren();});
$("chat-open-form").addEventListener("submit",e=>{e.preventDefault();busy($("chat-preview-button"),async()=>{
  const profile=state.profile,revision=state.workspaceRevision;linkPreview=null;$("chat-link-preview").replaceChildren();
  const preview=await json("interactions/preview",{link:$("chat-link").value},{profile});
  if(revision!==state.workspaceRevision||$("chat-link").value.trim()!==preview.link)return;linkPreview=preview;
  const box=$("chat-link-preview"),open=node("button","primary",tr("Join / open"));open.type="button";
  box.append(node("strong","",preview.title),node("code","target",preview.link));
  if(preview.about)box.append(node("p","",preview.about));
  const facts=[preview.participants_count!=null?tr("Members")+": "+preview.participants_count:"",
    preview.history_visible===true?tr("New members see earlier messages"):
    preview.history_visible===false?tr("New members do not see earlier messages"):""].filter(Boolean);
  if(facts.length)box.append(node("p","hint",facts.join(" · ")));
  const watch=node("label","check-label"),observe=node("input");observe.type="checkbox";observe.id="chat-link-observe";observe.checked=true;
  watch.append(observe,document.createTextNode(" "+tr("Observe: add this chat to sources")));
  box.append(node("p","hint",tr("The preview is saved. Opening a bot sends /start.")),watch,open);
  if(state.status?.actions?.read_only){open.disabled=true;box.append(node("p","hint",tr("This account is read-only. Turn it off on the account page.")));}
  open.addEventListener("click",()=>busy(open,async()=>{
    if(revision!==state.workspaceRevision||linkPreview!==preview)return;
    const result=await panelAction({action:"open",preview_id:preview.preview_id,observe:observe.checked},{profile,revision});
    if(!result||revision!==state.workspaceRevision)return;
    if(["succeeded","approval_pending","queued"].includes(result.status)){linkPreview=null;open.remove();observe.disabled=true;}
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

let chatProfileRead=null;
async function loadChatProfile(){
  const id=state.chat,revision=state.workspaceRevision,generation=chatGeneration;if(id===null||id===undefined)return;
  const options=viewOptions('chats');
  if(chatProfileRead?.id===id&&chatProfileRead.revision===revision&&chatProfileRead.generation===generation&&
      chatProfileRead.signal===options.signal)return chatProfileRead.promise;
  const read={id,revision,generation,signal:options.signal};
  read.promise=(async()=>{
    let r;
    try{r=await json("chats/"+encodeURIComponent(id)+"/profile",undefined,options);}
    catch(error){if(id===state.chat&&revision===state.workspaceRevision&&generation===chatGeneration&&!(error instanceof StaleView)){
      state.chatProfile={chat:id,error:true};if(state.chatView==='profile')renderChatFeed();}throw error;}
    if(id!==state.chat||revision!==state.workspaceRevision||generation!==chatGeneration)return;
    state.chatProfile={chat:id,...r};renderChatStatus();if(state.chatView==='profile')renderChatFeed();
  })();
  chatProfileRead=read;
  try{return await read.promise;}finally{if(chatProfileRead===read)chatProfileRead=null;}
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
  const chat=state.chat,profile=state.profile,revision=state.workspaceRevision,generation=chatGeneration;
  const current=()=>profile===state.profile&&revision===state.workspaceRevision&&chat===state.chat&&generation===chatGeneration;
  const work=async()=>{
    toast(tr("Loading the last {n} messages from Telegram…",{n:limit}));
    try{
      const r=await json("snapshot",{chat_id:chat,limit},{profile});
      if(!current())return;
      $("chat-history-feedback")?.remove();
      toast(tr("Loaded {n} messages.",{n:r.captured}));await refreshStatus();await refreshChats();
    }catch(error){
      if(!current()||error instanceof StaleView)return;
      $("chat-history-feedback")?.remove();
      const notice=viewState("error",tr("Could not load messages"),error.message,tr("Retry"),()=>current()?loadHistory(null,limit):undefined);
      notice.id="chat-history-feedback";$("chat-feed").before(notice);throw error;
    }
  };
  return button?busy(button,work):work();
}
$("chats-manage").addEventListener("click",()=>navigate("sources"));
$("chat-load-history").addEventListener("click",e=>loadHistory(e.currentTarget,Number($("chat-history-limit").value)));

let multiPoll=null,multiRequest=0,multiDiscovery=null;
const multiActive=x=>!!x&&["preparing","running","selecting","packaging"].includes(x.phase);
const multiRunning=()=>multiActive(state.multi);
const multiCurrent=(revision,token,request)=>revision===state.workspaceRevision&&token===state.token&&
  !!token&&!$("workspace").hidden&&request===multiRequest;
const multiRetryable=error=>!(error instanceof StaleView)&&
  (!error.status||[408,429].includes(error.status)||error.status>=500);
const multiRetryDelay=attempt=>Math.min(30000,1500*2**Math.min(attempt+1,5));
async function openExportDialog(){
  const chat=state.chat,profile=state.profile,revision=state.workspaceRevision,generation=chatGeneration;
  await loadProfiles();
  if(revision!==state.workspaceRevision||generation!==chatGeneration)return;
  show("toast",false);
  const info=state.chatInfo,basic=info?.kind==="group",facts=$("export-dialog-facts"),list=$("export-dialog-accounts");
  const takeoutOption=$("export-transport").querySelector('[value="takeout"]');
  takeoutOption.disabled=!["channel","supergroup"].includes(info?.kind);
  if(takeoutOption.disabled)$("export-transport").value="regular";
  facts.replaceChildren();list.replaceChildren();
  facts.append(node("p","export-fact",info?.title||tr("This chat")));
  if(basic)facts.append(node("p","export-fact warn",tr("This is an ordinary group: message numbers differ between accounts, so only this account can download it.")));
  function estimate(){
    const n=list.querySelectorAll("input:checked").length;
    $("export-dialog-estimate").textContent=tr("{n} idle accounts selected. Each account keeps its own connection and request limits.",{n});
    $("export-dialog-start").disabled=!n;
  }
  for(const p of state.profiles){
    const c=p.collector,lead=p.id===state.profile,connected=!!c?.has_session&&!p.error_type,account=c?.account;
    const row=node("label","export-account"),box=node("input"),who=node("span","export-account-who"),text=node("span");
    const limited=c?.rpc_backoff_until>Date.now()/1000;
    const occupied=limited||c?.running||c?.account_task||c?.available_for_export===false;
    box.type="checkbox";box.value=p.id;box.disabled=!connected||!!occupied||basic&&!lead;box.addEventListener("change",estimate);
    box.checked=!box.disabled&&(lead||!!exportPreselect?.has(p.id));
    text.append(node("b","",p.label),node("small","",limited?tr("Telegram rate limit: wait until {time}.",{
      time:formatTime(new Date(c.rpc_backoff_until*1000).toISOString())}):occupied?tr("Busy: pause the current task explicitly"):!connected?tr("no Telegram account connected"):
      basic?tr("not possible for ordinary groups"):account?(account.username?"@"+account.username+" · ":"")+"ID "+account.id:""));
    who.append(avatarNode(account?account.id:null,account&&account.username?account.username:p.label,"",p.id),text);
    row.append(box,who);list.append(row);
  }
  show("export-select-all",!basic&&state.profiles.length>1);
  $("export-select-all").onclick=()=>{list.querySelectorAll("input:not(:disabled)").forEach(b=>{b.checked=true;});estimate();};
  estimate();
  $("export-timezone").textContent=tr("Dates use your time zone: {zone}. Bounds are fixed at start.",{zone:Intl.DateTimeFormat().resolvedOptions().timeZone});
  const dialog=$("export-dialog");
  const saved=await json("multi-export/jobs",undefined,{root:true});
  if(revision!==state.workspaceRevision||generation!==chatGeneration)return;
  const jobs=$("export-saved-jobs");jobs.replaceChildren();
  const matching=(saved.jobs||[]).filter(j=>j.chat_id===chat);
  if(matching.length){
    jobs.append(node("b","",tr("Saved exports")));
    for(const job of matching){
      const button=node("button","text-link",fmtTime(job.started_at)+" · "+tr(job.phase)+" · "+(job.counts?.selected??job.captured));
      button.type="button";button.addEventListener("click",()=>{
        clearTimeout(multiPoll);++multiRequest;state.multi=job;state.multiHidden=null;
        dialog.close("saved");renderMulti();pollMulti(job.id);
      });jobs.append(button);
    }
  }
  $("export-dialog-cancel").onclick=()=>dialog.close("cancel");
  dialog.returnValue="";dialog.showModal();
  const choice=await new Promise(resolve=>dialog.addEventListener("close",()=>resolve(dialog.returnValue),{once:true}));
  if(choice!=="start"||revision!==state.workspaceRevision||generation!==chatGeneration)return;
  const profiles=[...list.querySelectorAll("input:checked")].map(b=>b.value);
  if(!profiles.length)throw new Error(tr("Select at least one idle account."));
  const dates=exportPeriod();
  const selection={...dates,languages:$("export-message-language").value?[$("export-message-language").value]:[],
    uncertain_language:$("export-uncertain-language").checked?"include":"exclude",reply_mode:$("export-reply-mode").value,
    reply_scope:$("export-reply-scope").value,context_depth:Number($("export-context").value),
    max_context_messages:Number($("export-context-limit").value),text_contains:$("export-text").value.trim()?[$("export-text").value.trim()]:[],
    download_media:$("export-media").checked};
  const x=await json("multi-export/start",{chat_id:chat,lead:profiles.includes(profile)?profile:profiles[0],profiles,selection,
    transport:$("export-transport").value},{root:true});
  state.multi=x;state.multiHidden=null;renderMulti();pollMulti(x.id);
  toast(tr("Export started with {n} accounts reserved exclusively for this task.",{n:profiles.length}));
}
function exportPeriod(){
  const preset=$("export-period").value,now=new Date();
  let from=null,to=null;
  if(preset==="7"||preset==="30"){to=now;from=new Date(now.getTime()-Number(preset)*86400000);}
  else if(preset==="month"){to=new Date(now.getFullYear(),now.getMonth(),1);from=new Date(now.getFullYear(),now.getMonth()-1,1);}
  else if(preset==="custom"){
    from=$("export-from").value?new Date($("export-from").value):null;
    to=$("export-to").value?new Date($("export-to").value):null;
  }
  if(from&&to&&from>=to)throw new Error(tr("The period must end after it starts."));
  return {from_utc:from?.toISOString()||null,to_utc:to?.toISOString()||null};
}
$("export-period").addEventListener("change",()=>{
  const custom=$("export-period").value==="custom";
  $("export-from").disabled=$("export-to").disabled=!custom;
});
$("export-from").disabled=$("export-to").disabled=true;
function renderMulti(){
  if(state.view!=='chats')return;
  if(state.multiChecked!==state.chat)void resumeMulti();
  const x=state.multi,box=$("export-box"),known=x&&!["none","unknown"].includes(x.phase);
  const running=multiActive(x),mine=known&&x.chat_id===state.chat;
  const percent=known&&x.ranges_total?Math.min(running?99:100,Math.floor(x.ranges_done*100/x.ranges_total)):null;
  $("chat-export-label").textContent=running&&mine?tr("Exporting")+(percent!==null?" "+percent+"%":"…"):tr("Export chat");
  show("chat-export-get",!!(mine&&x.phase==="done"&&x.ready));
  if(!mine||(!running&&state.multiHidden===x.id)){show("export-box",false);return;}
  box.replaceChildren();show("export-box",true);
  const head=node("div","export-head");
  const counts={title:x.title||tr("chat"),captured:(x.phase==="done"?x.counts?.selected??x.captured:x.captured).toLocaleString(),total:(x.total||0).toLocaleString(),percent};
  head.append(node("b","",running?tr("Exporting {title}: ",counts)+tr(x.total?"{captured} of {total} messages ({percent}%)":"{captured} messages",counts)+
    (x.eta_seconds?" · "+tr("{time} left",{time:fmtDuration(x.eta_seconds)}):""):x.phase==="done"?tr(x.ready?"Export ready: {captured} messages, signed.":"Export saved: {captured} messages, signed.",counts):
    x.phase==="failed"?tr("Export failed: {error}",{error:x.error||tr("unknown error")}):x.phase==="paused"?tr("Export paused; saved chunks are retained."):tr("Export cancelled.")));
  const action=(cls,label,work)=>{const b=node("button",cls+" small",label);b.type="button";b.addEventListener("click",()=>work(b));head.append(b);};
  if(running)action("quiet",tr("Pause"),b=>busy(b,async()=>{await json("multi-export/"+encodeURIComponent(x.id)+"/pause",{},{root:true});await pollMulti(x.id);}));
  if(["paused","failed","cancelled"].includes(x.phase))action("primary",tr("Resume saved chunks"),b=>busy(b,async()=>{await json("multi-export/"+encodeURIComponent(x.id)+"/resume",{},{root:true});await pollMulti(x.id);}));
  if(x.phase==="done"&&x.ready)action("primary",tr("Save signed export"),b=>saveMulti(b));
  if(!running)action("quiet",tr("Hide"),()=>{state.multiHidden=x.id;renderMulti();});
  box.append(head);
  box.append(node("p","hint",tr(x.transport==="takeout"?"Telegram Takeout session":"Regular session")));
  if(x.phase==="paused"&&x.error)box.append(node("p","hint",tr(x.error)));
  if(x.wait_until&&x.phase==="paused")box.append(node("p","hint",tr("Requests paused until")+": "+formatTime(new Date(x.wait_until*1000).toISOString())));
  if(Object.keys(x.transport_close_errors||{}).length)box.append(node("p","hint",tr("Takeout finalization is pending. The saved archive remains verifiable.")));
  box.append(node("p","hint",tr("Read {done} of {total} planned ranges.",{done:x.ranges_done||0,total:x.ranges_total||0})+" "+tr(x.phase)));
  if(x.performance){
    const p=x.performance,s=p.phase_seconds,seconds=value=>tr("{n} s",{
      n:value.toLocaleString(undefined,{maximumFractionDigits:1})});
    box.append(node("p","hint",tr("Current run: {messages} new messages · {time} elapsed.",{
      messages:p.new_messages.toLocaleString(),time:seconds(p.elapsed_seconds)})+
      (p.messages_per_second!==null?" "+tr("Acquisition: {rate} messages/s (including waits).",{
        rate:p.messages_per_second.toLocaleString(undefined,{maximumFractionDigits:1})}):"")));
    box.append(node("p","hint",tr("Preparation: {preparing}. Acquisition: {running}. Selection and attachments: {selecting}. Packaging and verification: {packaging}.",{
      preparing:seconds(s.preparing),running:seconds(s.running),selecting:seconds(s.selecting),packaging:seconds(s.packaging)})));
  }
  if(running&&x.disk)box.append(node("p","hint",tr("Disk space estimated at start: {needed} needed, {free} free.",{needed:humanSize(x.disk.needed_bytes),free:humanSize(x.disk.free_bytes)})));
  if(x.counts?.selected!==undefined)box.append(node("p","hint",tr("Examined: {examined}. Matches: {matched}. Context: {context}. Uncertain language: {uncertain}.",{
    examined:x.counts.examined,matched:x.counts.matched,context:x.counts.context,uncertain:x.counts.uncertain_language||0})));
  if(x.counts?.context_limit_reached)box.append(node("p","hint",tr("Context cap reached; additional context may be omitted.")));
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
  state.multiChecked=state.chat;
  try{
    const before=state.multi?.phase,x=await json("multi-export/"+encodeURIComponent(id),undefined,{root:true});
    if(!current())return;
    state.multi=x;renderMulti();
    if(multiActive(x))multiPoll=setTimeout(()=>{if(current())pollMulti(id);},1500);
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
  const chat=state.chat;
  if(state.multiChecked===chat||!state.token||!may("export")||$("workspace").hidden)return;
  if(multiDiscovery&&multiDiscovery.chat===chat&&multiCurrent(multiDiscovery.revision,multiDiscovery.token,multiDiscovery.request))return multiDiscovery.promise;
  clearTimeout(multiPoll);multiPoll=null;
  const request={revision:state.workspaceRevision,token:state.token,request:++multiRequest,chat};
  const current=()=>multiCurrent(request.revision,request.token,request.request)&&chat===state.chat;
  multiDiscovery=request;
  request.promise=(async()=>{
    try{
      const x=await json("multi-export/current"+(chat===null?"":"?chat_id="+encodeURIComponent(chat)),undefined,{root:true});
      if(!current())return;
      state.multiChecked=chat;
      state.multi=x?.id?x:null;renderMulti();
      if(multiActive(state.multi))pollMulti(x.id);
    }catch(e){
      if(!current()||e instanceof StaleView)return;
      if(multiRetryable(e))multiPoll=setTimeout(()=>{if(current())resumeMulti(attempt+1);},multiRetryDelay(attempt));
      else{state.multiChecked=chat;state.multi=null;renderMulti();}
      if(!attempt)toast(e.message,true);
    }finally{if(multiDiscovery===request)multiDiscovery=null;}
  })();
  return request.promise;
}
function saveMulti(button){return busy(button,async()=>{
  const x=state.multi;if(!x?.ready)throw new Error(tr("No finished export to save."));
  if(await download("multi-export/"+encodeURIComponent(x.id)+"/download",x.filename||"tgwitness-chat-export.zip",true,true)===false)return;
  renderMulti();toast(tr("Signed chat export saved."));
});}
let linkPlan=null,linkJob=null,linkPoll=null;
const LINK_REASONS={unavailable:"workspace unavailable",no_session:"no Telegram account connected",signed_out:"signed out: sign in again",
  observing:"observing: pause observation to include it",busy:"busy with another task",not_member:"not a member of this chat"};
function linkEstimate(){
  const p=linkPlan,n=$("link-export-plan").querySelectorAll("input[name=link-account]:checked").length;
  const table=p.estimates[$("link-export-transport").value]||p.estimates.regular,at=k=>table[Math.min(k,table.length)-1];
  const parts=[tr("1 account {time}",{time:fmtDuration(at(1))})];
  if(n>1)parts.push(tr("{n} selected accounts {time}",{n,time:fmtDuration(at(n))}));
  if(!p.single_account&&table.length>=10&&n!==10)parts.push(tr("10 accounts {time}",{time:fmtDuration(at(10))}));
  const transport=$("link-export-transport").value;
  $("link-export-estimate").textContent=tr("Estimated time:")+" "+parts.join(" · ")+". "+
    tr("Planning rate: {rate} messages/s per account ({source}).",{rate:p.rates[transport],source:tr(p.rate_sources[transport])});
  $("link-export-start").disabled=!n;
}
function renderLinkPlan(){
  const p=linkPlan,box=$("link-export-plan");box.replaceChildren();show("link-export-plan",true);
  const head=node("div","link-export-facts");head.append(node("b","",p.title||tr("Chat")));box.append(head);
  if(!p.readable){box.append(node("p","notice warning",tr(p.reason)));return;}
  const facts=[{channel:tr("Channel"),supergroup:tr("Group"),group:tr("Group")}[p.kind]||p.kind,
    tr("last message number {n}",{n:p.last_id.toLocaleString()})];
  if(p.visible!==null)facts.push(tr("{n} visible messages",{n:p.visible.toLocaleString()}));
  if(p.participants_count)facts.push(tr("{n} members",{n:p.participants_count.toLocaleString()}));
  head.append(node("span","hint",facts.join(" · ")));
  if(p.missing)box.append(node("p","hint",tr("Difference between last message number and visible count: {n}. This is a planning estimate.",{n:p.missing.toLocaleString()})));
  if(p.history_visible===false)box.append(node("p","hint",tr("New members do not see earlier history in this group.")));
  const label=node("label","",tr("History acquisition")+" "),select=node("select");select.id="link-export-transport";
  select.append(new Option(tr("Regular session"),"regular"));
  if(p.takeout_available)select.append(new Option(tr("Telegram Takeout session"),"takeout"));
  label.append(select);box.append(label);
  if(p.takeout_available)box.append(node("p","hint",tr("Takeout can accelerate public channel and supergroup history. Telegram may require export approval. Server-requested waits still apply.")));
  const accounts=node("fieldset","export-accounts");
  accounts.append(node("legend","",tr(p.single_account?"Account that downloads it":"Accounts that download it")));
  for(const a of p.accounts){
    const row=node("label","export-account"),box2=node("input"),who=node("span","export-account-who"),text=node("span");
    box2.type="checkbox";box2.name="link-account";box2.value=a.profile_id;box2.checked=a.chosen;box2.disabled=!a.usable;
    text.append(node("b","",a.label),node("small","",a.usable?[a.username?"@"+a.username:"",a.account_id?"ID "+a.account_id:""].filter(Boolean).join(" · "):
      a.reason==="rate_limited"?tr("Telegram rate limit: wait until {time}.",{time:formatTime(new Date(a.until*1000).toISOString())}):tr(LINK_REASONS[a.reason]||a.reason)));
    who.append(avatarNode(a.account_id,a.username||a.label,"",a.profile_id),text);row.append(box2,who);accounts.append(row);
    box2.addEventListener("change",()=>{
      if(p.single_account&&box2.checked)accounts.querySelectorAll("input[name=link-account]").forEach(other=>{if(other!==box2)other.checked=false;});
      linkEstimate();
    });
  }
  box.append(accounts);
  if(!p.accounts.some(a=>a.usable))box.append(node("p","notice warning",tr("No idle account can run this export. Pause observation or wait for other tasks, then check the link again.")));
  const estimate=node("p","export-estimate");estimate.id="link-export-estimate";box.append(estimate,node("p","hint",tr(p.estimate_scope)));
  const start=node("button","primary",tr("Start export"));start.type="button";start.id="link-export-start";
  start.addEventListener("click",()=>busy(start,startLinkExport));box.append(start);
  select.addEventListener("change",linkEstimate);linkEstimate();
}
async function startLinkExport(){
  const p=linkPlan,profiles=[...$("link-export-plan").querySelectorAll("input[name=link-account]:checked")].map(b=>b.value);
  if(!profiles.length)throw new Error(tr("Select at least one idle account."));
  const token=state.token,x=await json("multi-export/start",{chat_id:p.chat_id,lead:profiles.includes(p.reader)?p.reader:profiles[0],
    profiles,transport:$("link-export-transport").value,username:p.username||null},{root:true});
  if(state.token!==token)return;
  linkJob=x;renderLinkJob();pollLinkJob(x.id);
  toast(tr("Export started with {n} accounts reserved exclusively for this task.",{n:profiles.length}));
}
function renderLinkJob(){
  const x=linkJob,box=$("link-export-plan");box.replaceChildren();show("link-export-plan",true);
  const running=multiActive(x),percent=x.ranges_total?Math.min(running?99:100,Math.floor(x.ranges_done*100/x.ranges_total)):null;
  const counts={title:x.title||tr("chat"),captured:(x.phase==="done"?x.counts?.selected??x.captured:x.captured).toLocaleString(),total:(x.total||0).toLocaleString(),percent};
  box.append(node("b","",running?tr("Exporting {title}: ",counts)+tr(x.total?"{captured} of {total} messages ({percent}%)":"{captured} messages",counts):
    x.phase==="done"?tr(x.ready?"Export ready: {captured} messages, signed.":"Export saved: {captured} messages, signed.",counts):
    x.phase==="failed"?tr("Export failed: {error}",{error:x.error||tr("unknown error")}):x.phase==="paused"?tr("Export paused; saved chunks are retained."):tr("Export cancelled.")));
  if(running&&percent!==null){const bar=node("progress","export-bar");bar.max=100;bar.value=percent;bar.setAttribute("aria-label",tr("Export progress"));box.append(bar);}
  box.append(node("p","hint",tr("Read {done} of {total} planned ranges.",{done:x.ranges_done||0,total:x.ranges_total||0})+" "+tr(x.phase)));
  if(x.phase==="paused"&&x.error)box.append(node("p","hint",tr(x.error)));
  if(x.performance)box.append(node("p","hint",tr("Current run: {messages} new messages · {time} elapsed.",{
    messages:x.performance.new_messages.toLocaleString(),time:tr("{n} s",{n:Math.round(x.performance.elapsed_seconds).toLocaleString()})})));
  const actions=node("div","route-actions"),action=(cls,label,work)=>{
    const b=node("button",cls,label);b.type="button";b.addEventListener("click",()=>busy(b,work));actions.append(b);};
  if(running)action("quiet",tr("Pause"),async()=>{await json("multi-export/"+encodeURIComponent(x.id)+"/pause",{},{root:true});await pollLinkJob(x.id);});
  if(["paused","failed","cancelled"].includes(x.phase))action("primary",tr("Resume saved chunks"),async()=>{
    await json("multi-export/"+encodeURIComponent(x.id)+"/resume",{},{root:true});await pollLinkJob(x.id);});
  if(x.phase==="done"&&x.ready)action("primary",tr("Save signed export"),async()=>{
    if(await download("multi-export/"+encodeURIComponent(x.id)+"/download",x.filename||"tgwitness-chat-export.zip",true,true)===false)return;
    toast(tr("Signed chat export saved."));});
  if(!running)action("quiet",tr("Start over with another link"),async()=>{resetLinkExport();$("link-export-input").focus();});
  box.append(actions);
}
async function pollLinkJob(id){
  clearTimeout(linkPoll);linkPoll=null;
  const token=state.token;
  try{
    const x=await json("multi-export/"+encodeURIComponent(id),undefined,{root:true});
    if(state.token!==token||linkJob?.id!==id)return;
    linkJob=x;renderLinkJob();
    if(multiActive(x))linkPoll=setTimeout(()=>pollLinkJob(id),1500);
  }catch(e){
    if(e instanceof StaleView||state.token!==token||linkJob?.id!==id)return;
    if(multiRetryable(e))linkPoll=setTimeout(()=>pollLinkJob(id),5000);
    else toast(e.message,true);
  }
}
function resetLinkExport(){
  clearTimeout(linkPoll);linkPoll=null;linkPlan=linkJob=null;
  $("link-export-plan").replaceChildren();show("link-export-plan",false);$("link-export-input").value="";
}
$("link-export-form").addEventListener("submit",e=>{e.preventDefault();busy(e.submitter,async()=>{
  const link=$("link-export-input").value.trim();
  if(!link)throw new Error(tr("Paste a chat link or @username."));
  clearTimeout(linkPoll);linkPoll=null;linkJob=linkPlan=null;show("link-export-plan",false);
  const token=state.token,plan=await json("multi-export/plan",{link},{root:true});
  if(state.token!==token)return;
  linkPlan=plan;renderLinkPlan();
});});
window.addEventListener("tgwitness:lock",resetLinkExport);
$("chat-export-start").addEventListener("click",e=>busy(e.currentTarget,openExportDialog));
$("chat-export-get").addEventListener("click",e=>saveMulti(e.currentTarget));

function localInput(unix){
  if(!unix)return "";const d=new Date(unix*1000);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);
}
function workspaceName(id){return state.profiles?.find(p=>p.id===id)?.label||id||"";}
function accessScope(g){
  if(g.all_workspaces)return tr("All workspaces");
  const groups=(g.groups||[]).map(id=>tr("Group {name}: every account",{name:state.access?.groups?.find(x=>x.id===id)?.label||id}));
  return [...groups,...Object.entries(g.workspaces).map(([id,chats])=>chats===null?tr("{workspace}: every chat",{workspace:workspaceName(id)}):
    trn("{workspace}: {n} chat","{workspace}: {n} chats",chats.length,{workspace:workspaceName(id)}))].join("; ");
}
let accessGroupChoice=[];
function renderAccessGroups(selected){
  const box=$("access-group-list"),groups=state.access?.groups||[];
  if(selected)accessGroupChoice=selected;else if(box.childElementCount)accessGroupChoice=[...box.querySelectorAll("input:checked")].map(x=>x.value);
  const checked=accessGroupChoice;
  box.replaceChildren(...groups.map(group=>{
    const label=node("label","check-label"),input=document.createElement("input");
    input.type="checkbox";input.value=group.id;input.dataset.group=group.id;input.checked=checked.includes(group.id);input.disabled=$("access-all").checked;
    label.append(input,document.createTextNode(" "+tr("Group {name}",{name:group.label})+" · "+trn("{n} account","{n} accounts",group.members.length)));return label;
  }));
  $("access-groups").hidden=!groups.length;
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
  renderAccessWorkspaces(g?g.workspaces:{[state.profile]:null});renderAccessGroups(g?.groups||[]);accessView?.syncForm();
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
    groups:$("access-all").checked?[]:[...$("access-group-list").querySelectorAll("input:checked")].map(x=>x.value),
    permissions:[...$("access-permissions").querySelectorAll("input:checked")].map(x=>x.value),
    ips:$("access-ips").value.split(/\s+/).filter(Boolean),bind_first_ip:$("access-bind").checked,
    max_uses:uses?Number(uses):null,expires_at:expires?new Date(expires).getTime()/1000:null,
    max_sessions:Number($("access-sessions").value),on_limit:$("access-on-limit").value,
    session_minutes:Number($("access-idle").value)};
}
function sessionOwner(s){return s.admin?tr("Main administrator"):s.label;}
function renderAccess(){
  const a=state.access;if(!a)return;
  state.accessNames=state.me?.admin?a.names||{}:{};
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
      if(!(await askConfirm(tr("Revoke the access of \"{name}\"? Its open sessions end at once.",{name:g.label}),{danger:true,confirmText:tr("Revoke")})))return;
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
        tr("last activity {time}",{time:formatTime(s.last_seen_at)}),trn("{n} request","{n} requests",s.requests)].join(" · ")));
    end.addEventListener("click",()=>busy(end,async()=>{
      if(!(await askConfirm(tr("End this session? Its open panel will be locked."),{danger:true})))return;
      accessLoadSerial++;
      state.access=await json("access/sessions/"+encodeURIComponent(s.id),undefined,{root:true,method:"DELETE"});renderAccess();
    }));
    row.append(info,end);if(old){if(old.firstElementChild.outerHTML!==info.outerHTML)old.firstElementChild.replaceWith(info);sessionRows.push(old);}else sessionRows.push(row);
  }
  placeChildren(sessions,sessionRows);
}
let topologyView=null;
const topologyReady=import('./views/topology.js?v=2').then(({createTopology})=>{
  topologyView=createTopology({root:$('view-topology'),tr,json,getState:()=>state,options:()=>viewOptions('topology'),toast,
    openSettings:async (profile,card)=>{
      if(profile&&state.profile!==profile&&await switchProfile(profile)===false)return;
      await navigate(card||'connection');
    }});
  return topologyView;
});
topologyReady.catch(error=>toast(error.message,true));
let accessView=null,systemLogView=null;
let systemMapView=null;
const systemMapReady=import('./views/system-map.js?v=2').then(({createSystemMap})=>{
  systemMapView=createSystemMap({root:$('view-system-map'),tr,json,getState:()=>state,
    options:()=>viewOptions('system-map'),
    openSettings:async (profile,card)=>{
      if(profile&&state.profile!==profile&&await switchProfile(profile)===false)return;
      if(['connection','integrations','analysis'].includes(card)){await navigate(card);return;}
      await navigate(card?'witness':'connection');
      if(card&&state.view==='witness')selectExtra(card);
    },toast});
  return systemMapView;
});
systemMapReady.catch(error=>toast(error.message,true));
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
  if(!accessFormReady){renderAccessForm(state.accessEdit);accessFormReady=true;}
  if(!adminLimitsReady)$("access-admin-form").inert=true;
  const view=await accessReady;if(state.view!=='access'||!state.me?.admin)return;view.enter();
  const serial=++accessLoadSerial,result=await json("access",undefined,{root:true,...viewOptions('access')});
  if(serial!==accessLoadSerial||state.view!=='access')return;
  state.access=result;state.accessNames=result.names||{};
  if(!adminLimitsDirty){
    $("admin-sessions").value=state.access.admin.max_sessions;$("admin-on-limit").value=state.access.admin.on_limit;
    $("admin-idle").value=state.access.admin.session_minutes;
  }
  adminLimitsReady=true;$("access-admin-form").inert=false;
  renderAccessGroups();renderAccess();
}
$("access-refresh").addEventListener("click",e=>busy(e.currentTarget,()=>loadAccess()));
$("access-all").addEventListener("change",()=>[...$("access-workspaces").querySelectorAll("input,select"),...$("access-group-list").querySelectorAll("input")]
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
$("panel-key-rotate").addEventListener("click",event=>busy(event.currentTarget,async()=>{
  let owner=actionOwner();
  if(!(await askConfirm(tr("Replace the administrator key and end all current browser sessions? Save the new key after this step."),{danger:true})))return;
  if(!owner.current())return;
  const inert=$("workspace").inert;
  window.TgWitnessLive?.stop();state.workspaceRevision++;owner=actionOwner();$("workspace").inert=true;
  try{
    const result=await json("access/token",{},{root:true,token:owner.token});
    if(!owner.current())throw new StaleView();
    state.token=result.session;state.me=result.me;state.workspaceRevision++;owner=actionOwner();
    sessionStorage.setItem("tgwitness-token",state.token);
    $("panel-key-new").value=result.token;show("panel-key-result",true);
    await loadAccess();
  }finally{if(owner.current()){$("workspace").inert=inert;syncLive();}}
}));
$("panel-key-copy").addEventListener("click",event=>busy(event.currentTarget,async()=>{
  await navigator.clipboard.writeText($("panel-key-new").value);toast(tr("Token copied."));
}));
$("panel-key-hide").addEventListener("click",()=>{$("panel-key-new").value="";show("panel-key-result",false);});
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
    if(state.view==="accounts"||state.view==="group") await loadProfiles();
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
      $("gate-help").textContent=tr("For your own groups, start your own panel with tgwitness and a separate data directory. Demo data cannot be converted into a real investigation.");
    }
  }catch(error){                                                                     }
  if(!accessStarted&&revision===state.workspaceRevision&&state.token)
    await unlock().catch(unlockFailed);
}
bootstrap();
