const paths={start:"start",chats:"chats",observations:"journal",sources:"sources",parameters:"parameters",accounts:"accounts",
  access:"access","system-log":"system-log",integrations:"integrations",evidence:"exports",witness:"extras",connection:"account",analysis:"analysis",sealed:"sealed"};
const views=Object.fromEntries(Object.entries(paths).map(([view,path])=>[path,view]));
const legacy={start:"start",account:"connection",connection:"connection",journal:"observations",observations:"observations",
  exports:"evidence",evidence:"evidence",extras:"witness",witness:"witness",sealed:"sealed",chats:"chats",
  sources:"sources",parameters:"parameters",accounts:"accounts",access:"access","system-log":"system-log",integrations:"integrations",analysis:"analysis"};
const cards=new Set(["alerts","evidence","cloud","bot","github"]);
const workspacePattern=/^(?:default|[a-f0-9]{32})$/;
const integer=value=>/^-?\d+$/.test(value||"")&&Number.isSafeInteger(Number(value))&&Number(value)!==0?Number(value):null;

export function parseRoute(value,{workspace="default",staticDemo=false}={}){
  const url=value instanceof URL?value:new URL(value,location.href),query=url.searchParams;
  let path=query.get("route")||(staticDemo?"/":url.pathname),fragment=url.hash.slice(1);
  try{fragment=decodeURIComponent(fragment);}catch{fragment="";}
  if(fragment.startsWith("/"))path=fragment;
  const oldView=legacy[fragment];
  if(oldView)path="/"+paths[oldView];
  const parts=path.replace(/^\/+|\/+$/g,"").split("/").filter(Boolean);
  const explicit=!!query.get("route")||!!oldView||parts.length>0&&parts[0]!=="index.html"||query.has("event");
  const route={view:views[parts[0]]||null,workspace:query.get("ws")||query.get("workspace")||workspace,
    chatId:null,seq:null,kind:query.get("kind")||"",source:query.get("source")||"",q:query.get("q")||"",
    since:query.get("since")||"",until:query.get("until")||"",system:query.get("system")==="1",
    before:query.has("before")?integer(query.get("before")):null,extra:null,section:null,explicit};
  if(!workspacePattern.test(route.workspace))route.error="Unknown workspace.";
  if(parts[0]==="chats"&&parts.length>1){route.chatId=integer(parts[1]);if(route.chatId===null||parts.length>2)route.error="Record is unavailable to this access.";}
  if(parts[0]==="journal"&&parts.length>1){
    route.seq=parts[1]==="event"&&parts.length===3?integer(parts[2]):null;
    if(route.seq===null||route.seq<=0)route.error="Record is unavailable to this access.";
  }
  if(parts[0]==="extras"&&parts.length>1){route.extra=parts[1];if(!cards.has(route.extra)||parts.length>2)route.error="Record is unavailable to this access.";}
  if(parts.length>1&&!["chats","journal","extras"].includes(parts[0]))route.error="Record is unavailable to this access.";
  if(query.has("event")){
    route.seq=integer(query.get("event"));route.view="observations";
    if(route.seq===null||route.seq<=0)route.error="Record is unavailable to this access.";
  }
  if(route.view==="parameters"&&!oldView&&fragment&&!fragment.startsWith("/"))route.section=fragment.replace(/^parameters-group-/,"");
  if(explicit&&!route.view)route.error="Record is unavailable to this access.";
  if(route.source&&integer(route.source)===null)route.error="Record is unavailable to this access.";
  if(query.has("before")&&(route.before===null||route.before<=0))route.error="Record is unavailable to this access.";
  return route;
}

export function routeURL(route,{base=location.href,staticDemo=false}={}){
  const current=new URL(base),url=new URL(base),query=new URLSearchParams();
  let path="/"+(paths[route.view]||"chats");
  if(route.view==="chats"&&route.chatId!==null&&route.chatId!==undefined)path+="/"+route.chatId;
  if(route.view==="observations"&&route.seq)path+="/event/"+route.seq;
  if(route.view==="witness"&&route.extra)path+="/"+encodeURIComponent(route.extra);
  if(staticDemo)query.set("route",path);else url.pathname=path;
  query.set("ws",route.workspace||"default");
  if(current.searchParams.has("lang"))query.set("lang",current.searchParams.get("lang"));
  if(route.view==="observations")for(const key of ["kind","source","q","since","until"])if(route[key])query.set(key,route[key]);
  if(route.view==="observations"&&route.system)query.set("system","1");
  if(route.view==="observations"&&route.before)query.set("before",route.before);
  url.search=query.toString();url.hash=route.view==="parameters"&&route.section?encodeURIComponent(route.section):"";
  return url;
}

export function createRouter(context){
  const staticDemo=!!window.TGW_ONLINE_DEMO||/\/demo(?:\/index\.html|\/)?$/.test(location.pathname);
  let generation=0,lastReplay=null,started=false;
  const parse=()=>parseRoute(location.href,{workspace:context.snapshot().workspace,staticDemo});
  const href=patch=>routeURL({...context.snapshot(),...patch},{staticDemo}).href;
  const emit=(route,reason)=>window.dispatchEvent(new CustomEvent("tgwitness:route",{detail:{view:route.view,workspace:route.workspace,route,reason}}));
  function record(patch={},options={}){
    if(!context.ready())return;
    generation++;lastReplay=null;
    const route={...context.snapshot(),...patch},url=routeURL(route,{staticDemo});
    const method=options.replace||url.href===location.href?"replaceState":"pushState";
    history[method]({tgwitness:{route}},"",url);
    lastReplay=location.href;
    emit(route,options.replace?"replace":"navigate");
  }
  async function replay(reason="history"){
    if(!context.ready())return;
    const expected=++generation,route=parse(),valid=()=>expected===generation&&context.ready();
    lastReplay=location.href;
    if(route.error){context.error(route.error);return;}
    if(!route.view){record({}, {replace:true});return;}
    try{
      await context.apply(route,valid);
      if(!valid())return;
      const final={...context.snapshot(),...route,view:context.snapshot().view};
      history.replaceState({tgwitness:{route:final}},"",routeURL(final,{staticDemo}));
      lastReplay=location.href;
      emit(final,reason);
    }catch(error){if(valid()&&error.name!=="StaleView")context.error(error.message);}
  }
  const onHistory=()=>{if(lastReplay!==location.href)void replay();};
  window.addEventListener("popstate",onHistory);window.addEventListener("hashchange",onHistory);
  return {
    record,href,parse,
    async start(){started=true;if(parse().explicit)await replay("initial");else record({}, {replace:true});},
    get started(){return started;},
    invalidate(){generation++;lastReplay=null;},
    destroy(){generation++;window.removeEventListener("popstate",onHistory);window.removeEventListener("hashchange",onHistory);},
  };
}
