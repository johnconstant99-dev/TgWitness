const viewerMeta=JSON.parse(($("#viewer-meta")||{}).textContent||"null");
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const nf=new Intl.NumberFormat(lang),num=n=>nf.format(n||0);
const dateFmt=(options)=>{try{return new Intl.DateTimeFormat(lang,{...options,timeZone:"UTC"});}catch(e){return null;}};
const fullFmt=dateFmt({dateStyle:"medium",timeStyle:"medium"}),dayFmt=dateFmt({dateStyle:"full"}),
  clockFmt=dateFmt({hour:"2-digit",minute:"2-digit"}),secFmt=dateFmt({hour:"2-digit",minute:"2-digit",second:"2-digit"});
const stamp_=(f,v,tail)=>{if(!v)return"";const d=new Date(v);return isNaN(d)||!f?String(v):f.format(d)+(tail||"");};
const when=v=>stamp_(fullFmt,v," UTC"),dayOf=v=>stamp_(dayFmt,v),clock=v=>stamp_(clockFmt,v),clockSec=v=>stamp_(secFmt,v);
const sha=async data=>hex(await crypto.subtle.digest("SHA-256",typeof data==="string"?new TextEncoder().encode(data):data));
const fill=(text,values)=>text.replace(/\{(\w+)\}/g,(m,k)=>k in values?values[k]:m);
const sayf=(key,values)=>fill(say(key),values||{});
const human=k=>{const w=String(k||"").replace(/[._]+/g," ").trim();return w?w[0].toUpperCase()+w.slice(1):"";};
const span=s=>{s=Math.round(s||0);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return [d?sayf("{n} d",{n:num(d)}):"",h?sayf("{n} h",{n:num(h)}):"",m&&!d?sayf("{n} min",{n:num(m)}):""].filter(Boolean).join(" ")||sayf("{n} s",{n:num(s)});};
const initials=s=>String(s||"?").trim().split(/\s+/).slice(0,2).map(w=>w[0]||"").join("").toUpperCase()||"?";
const colour=v=>"c"+(Math.abs([...String(v)].reduce((a,c)=>a*31+c.charCodeAt(0)|0,7))%7);
const ic=name=>'<svg class="i" aria-hidden="true"><use href="#i-'+name+'"/></svg>';
const SEARCH='<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.6-3.6"/></svg>';
const CAT={message:["message","blue"],text:["message","blue"],edited:["edit","orange"],deleted:["trash","red"],media:["file","violet"],
  reaction:["tag","teal"],member:["users","green"],system:["settings","slate"],service:["settings","slate"]};
const defang=(kind,v)=>{v=String(v);if(kind==="url"||kind==="telegram-invite"){const m=v.match(/^([a-z]+):\/\/([^/]*)(.*)$/i);
  return m?m[1].replace(/http/i,"hxxp")+"[://]"+m[2].replace(/\./g,"[.]")+m[3]:v;}
  if(kind==="domain")return v.replace(/\./g,"[.]");if(kind==="email"){const [a,b]=v.split("@");return a+"[@]"+String(b||"").replace(/\./g,"[.]");}return v;};
function save(name,text,type){const url=URL.createObjectURL(new Blob([text],{type}));const a=document.createElement("a");
  a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),20000);}
if(viewerMeta)startViewer(viewerMeta).catch(e=>{const box=$("#view-data");if(box)box.innerHTML='<div class="v-empty bad">'+esc(String(e))+"</div>";console.error(e);});

async function startViewer(meta){
  const chat=meta.kind==="chat";
  const V={items:[],byKey:new Map(),people:[],iocs:[],iocKeys:new Map(),selected:new Set(),results:[],from:0,to:0,
    files:{ok:0,bad:[],missing:[]},source:null,
    filter:{q:"",cats:new Set(Object.keys(meta.cats).filter(c=>!(meta.hidden||[]).includes(c))),chats:new Set(),people:new Set(),
      keys:null,keysLabel:"",from:"",to:"",only:new Set(),sort:"asc"}};
  const tabs=$$(".tabs [data-view]"),views=$$(".view");
  const bar=$(".bar");if(bar&&window.ResizeObserver)new ResizeObserver(()=>{
    document.documentElement.style.setProperty("--bar-height",Math.ceil(bar.getBoundingClientRect().height)+"px");
  }).observe(bar);
  const show=name=>{for(const v of views)v.hidden=v.id!=="view-"+name;for(const t of tabs)t.setAttribute("aria-current",String(t.dataset.view===name));
    history.replaceState(null,"",name==="report"?location.pathname+location.search:"#"+name);window.scrollTo(0,0);};
  for(const t of $$("[data-view]"))t.addEventListener("click",e=>{e.preventDefault();show(t.dataset.view);});
  document.addEventListener("click",e=>{const a=e.target.closest("a[data-goto]");if(!a)return;e.preventDefault();show("data");goto(a.dataset.goto);});
  for(const a of $$(".toc a,.brand,#seal-hint"))a.addEventListener("click",()=>show("report"));
  const start=(location.hash||"").slice(1);if(["data","people","iocs","check"].includes(start))show(start);

  $("#view-data").innerHTML='<div class="console"><button type="button" class="v-btn ghost v-filter-toggle" id="v-filter-toggle" aria-expanded="false" aria-controls="v-filters">'+ic("settings")+esc(say("Filters"))+'</button><aside class="v-filters" id="v-filters" aria-label="'+esc(say("Filters"))+'">'
    +'<div class="v-group"><h4>'+esc(say("Show"))+'</h4><div class="v-chips" id="v-cats"></div></div>'
    +(chat?"":'<div class="v-group" id="v-chats-box"><h4>'+esc(say("Chats"))+'</h4><div class="v-checks" id="v-chats"></div></div>')
    +'<div class="v-group"><h4>'+esc(chat?say("Participants"):say("Senders"))+'</h4><input type="search" id="v-people-q" placeholder="'
    +esc(say("Find a person"))+'"><div class="v-checks" id="v-people"></div></div>'
    +'<div class="v-group"><h4>'+esc(say("Period (UTC)"))+'</h4><div class="v-dates"><label>'+esc(say("From"))+'<input type="date" id="v-from"></label><label>'
    +esc(say("To"))+'<input type="date" id="v-to"></label></div></div>'
    +'<div class="v-group"><h4>'+esc(say("Only"))+'</h4><div class="v-checks v-switches" id="v-only"></div></div>'
    +'<button type="button" class="v-reset" id="v-reset">'+esc(say("Reset filters"))+"</button></aside>"
    +'<section class="v-results"><div class="v-top"><div class="v-searchbar">'+SEARCH+'<input type="search" id="v-q" autocomplete="off" placeholder="'
    +esc(say("Search: words, \"a phrase\", #number, @username"))+'"><input class="v-jump" type="text" id="v-jump" inputmode="numeric" placeholder="'+esc(say("Go to #"))+'">'
    +'<select id="v-sort" aria-label="'+esc(say("Order"))+'"><option value="asc">'+esc(say("Oldest first"))+'</option><option value="desc">'+esc(say("Newest first"))+"</option></select></div>"
    +'<div class="v-meta"><span><b id="v-count" role="status">…</b></span><span class="v-verified" id="v-status" role="status">'+ic("shield")+"<span>"+esc(say("Loading the signed data…"))+"</span></span>"
    +'<div class="v-active" id="v-active"></div><button type="button" class="v-link push" id="v-pick-all">'+esc(say("Select shown"))+"</button></div></div>"
    +'<button type="button" class="v-btn ghost v-earlier" id="v-earlier" hidden>'+esc(say("Show earlier"))+"</button>"
    +'<div class="v-feed '+(chat?"chat":"journal")+'" id="v-list" role="list"></div><div id="v-more" class="v-sentinel"></div></section>'
    +'<aside class="v-detail" id="v-detail" hidden></aside></div>'
    +'<div class="v-selbar" id="v-selbar" hidden><b id="v-selcount"></b><button type="button" class="v-btn ghost" data-sel="only">'+esc(say("Show selected"))
    +'</button><button type="button" class="v-btn ghost" data-sel="print">'+esc(say("Print"))+'</button><button type="button" class="v-btn" data-sel="json">'
    +esc(say("Save extract (JSON)"))+'</button><button type="button" class="v-btn ghost" data-sel="csv">'+esc(say("Save as CSV"))
    +'</button><button type="button" class="v-btn ghost" data-sel="clear" aria-label="'+esc(say("Clear"))+'">'+ic("x")+"</button></div>";
  const status=$("#v-status"),countBox=$("#v-count");
  $("#v-filter-toggle").onclick=e=>{const button=e.currentTarget,expanded=button.getAttribute("aria-expanded")!=="true";
    button.setAttribute("aria-expanded",String(expanded));$("#v-filters").classList.toggle("expanded",expanded);};
  for(const id of ["v-q","v-jump","v-people-q"]){const input=$("#"+id);input.setAttribute("aria-label",input.placeholder);}
  const setStatus=(tone,text,extra)=>{status.className="v-verified "+tone;status.innerHTML=ic(tone==="ok"?"shield":"alert")+"<span>"+esc(text)+"</span>"+(extra||"");};

  const seal=node?JSON.parse(node.textContent):null,descriptor=seal&&seal.statement&&seal.statement.subject&&seal.statement.subject.viewer;
  let sealOk=false,sealInvalid=false;try{const r=await opened(node.textContent);sealOk=r.ok&&r.fp===(stamp&&stamp.dataset.fp);sealInvalid=!sealOk;}catch(e){sealOk=false;}
  if(sealInvalid){setStatus("bad",say("The seal signature is not valid."));countBox.textContent="0";return;}
  if(!descriptor||!descriptor.files||!descriptor.files.length){setStatus("warn",descriptor&&descriptor.omitted?
    say("This report was saved without its data. Open report.html inside the archive for the viewer."):say("No data in this report."));
    countBox.textContent="0";return;}
  const fromScript=file=>new Promise(resolve=>{
    if(!/^viewer\/[a-z0-9-]+\.html$/.test(file)){resolve(null);return;}
    const frame=document.createElement("iframe");frame.hidden=true;frame.sandbox="allow-scripts";
    const done=text=>{clearTimeout(timer);window.removeEventListener("message",receive);frame.remove();resolve(text);};
    const receive=e=>{if(e.source===frame.contentWindow&&e.data&&e.data.file===file&&(typeof e.data.text==="string"||e.data.text===null))done(e.data.text);};
    const timer=setTimeout(()=>done(null),10000);window.addEventListener("message",receive);
    frame.src=file;
    document.body.append(frame);});
  const fromSource=async file=>{if(!V.source)return null;const text=await V.source(file);if(text==null)return null;
    const doc=new DOMParser().parseFromString(text,"text/html"),node=doc.querySelector('script#data[type="application/json"]');
    if(!node)return null;const payload=JSON.parse(node.textContent);return payload.file===file&&typeof payload.text==="string"?payload.text:null;};
  const read=async file=>{const inline=$('script.tgw-file[data-file="'+file+'"]');if(inline)return inline.textContent;
    return V.source?fromSource(file):fromScript(file);};
  const accept=(f,text)=>{const value=JSON.parse(text);
    if(f.role==="items")for(const raw of value)add(raw);else if(f.role==="people")V.people=value;else if(f.role==="indicators")V.iocs=value;};
  const add=raw=>{const it=chat?chatItem(raw):journalItem(raw);V.items.push(it);V.byKey.set(it.key,it);};
  async function loadAll(files){let done=0;
    for(const f of files){const text=await read(f.file);done++;setStatus("",sayf("Checking data files: {a} of {b}",{a:done,b:files.length}));
      if(text==null){V.files.missing.push(f.file);continue;}
      if(await sha(text)!==f.sha256){V.files.bad.push(f.file);continue;}
      try{accept(f,text);V.files.ok++;}catch(e){V.files.bad.push(f.file);}}}
  await loadAll(descriptor.files);
  finish();

  function finish(){
    V.items.sort((a,b)=>a.n-b.n);
    if(!chat||!V.people.length)V.people=aggregatePeople();
    V.iocKeys=new Map();V.iocs.forEach((x,i)=>{for(const ref of x.refs||[]){const key=refKey(ref);if(!key)continue;
      if(!V.iocKeys.has(key))V.iocKeys.set(key,[]);V.iocKeys.get(key).push(i);}});
    for(const it of V.items){const list=V.iocKeys.get(it.key)||[];it.wallet=list.some(i=>V.iocs[i].kind==="wallet");
      it.link=it.link||list.some(i=>["url","domain","telegram-invite"].includes(V.iocs[i].kind));}
    const bad=V.files.bad.length,missing=V.files.missing.length;
    if(bad)setStatus("bad",sayf("{n} data files do not match the seal and are not shown",{n:bad}));
    else if(missing)setStatus("warn",sayf("{n} data files were not found next to this page",{n:missing}),
      ' <button type="button" class="v-link" data-view="check">'+esc(say("Open the archive to load them"))+"</button>");
    else if(sealOk)setStatus("ok",sayf("{n} data files match the signed seal",{n:V.files.ok}));
    else setStatus("warn",say("The seal signature could not be checked in this browser"));
    for(const b of status.querySelectorAll("[data-view]"))b.addEventListener("click",()=>show("check"));
    for(const t of tabs)if(t.dataset.view==="data")t.querySelector("b").textContent=num(V.items.length);
    if(!V.bound){bindControls();V.bound=true;}buildFilters();apply();buildPeople();buildIocs();buildCheck();}

  // ---- Items: one shape for chat messages and journal records ----
  function chatItem(r){const d=r||{};const file=d.file?{path:d.file,sha:d.file_sha256,size:d.file_size,kind:d.file_kind,mime:(d.media_info||{}).mime_type}:null;
    const it={key:"m"+d.id,n:d.id,at:d.date,who:d.from||(d.from_id!=null?"ID "+d.from_id:say("Unknown")),user:d.from_username,uid:d.from_id,
      text:d.text||"",cat:d.type==="service"?"service":d.media_type?"media":d.edited?"edited":"text",d,file,raw:r,
      service:d.type==="service"?actionText(d.action)+(d.action_title?" · “"+d.action_title+"”":""):"",edited:d.edited,found:d.found_on_recheck};
    it.link=(d.text_entities||[]).some(x=>x.href||x.type==="link");return finishItem(it);}
  function journalItem(j){const d=j.d||{};const it={key:"r"+j.s,n:j.s,at:j.t,chat:j.ch,msg:j.m,who:j.a||(j.id!=null?"ID "+j.id:""),user:j.u,uid:j.id,
      text:j.x||"",cat:j.c,kind:j.k,d,hash:j.h,sent:Object.hasOwn(j,"sent_at")?j.sent_at:j.tt,edited:j.edited_at,p:j.p,withheld:j.w,textWithheld:j.xw,raw:j,
      file:j.f?{path:"media/"+j.f.sha,sha:j.f.sha,mime:j.f.mime,size:j.f.size,name:j.f.name}:null};
    it.link=(d.text_entities||[]).some(x=>x.href||x.type==="link");return finishItem(it);}
  function finishItem(it){const d=it.d||{},parts=[it.text,it.who,it.user?"@"+it.user:"",it.uid,"#"+it.n,it.service||"",title(it.chat),it.p||""];
    for(const x of d.text_entities||[])parts.push(x.text||"",x.href||"");
    for(const row of (d.buttons&&d.buttons.rows)||[])for(const b of row)parts.push(b.text||"",b.url||"");
    if(it.file)parts.push(it.file.name||"",it.file.sha||"");if(d.media_info)parts.push(d.media_info.file_name||"",d.media_info.url||"");
    it.hay=parts.join("\n").toLowerCase();return it;}
  function title(id){return id==null?"":(meta.titles||{})[String(id)]||say("Chat")+" "+id;}
  function kindLabel(it){return chat?(meta.cats||{})[it.cat]||"":(meta.kinds||{})[it.kind]||human(it.kind);}
  function actionText(a){const w=String(a||"").replace("MessageAction","").replace(/(?!^)([A-Z])/g," $1").trim();return w?w[0].toUpperCase()+w.slice(1).toLowerCase():say("Service message");}
  function refKey(ref){return ref.seq!=null?"r"+ref.seq:ref.message!=null?"m"+ref.message:null;}
  function isImage(it){const f=it.file;return !!f&&(/^image\//.test(f.mime||"")||f.kind==="photo"||String((it.d||{}).media_type||"").includes("Photo"));}
  function aggregatePeople(){const map=new Map();
    for(const it of V.items){if(it.uid==null&&!it.who)continue;if(!["message","edited","text","media"].includes(it.cat))continue;
      const id=String(it.uid??it.who);const p=map.get(id)||{user_id:it.uid,name:it.who,username:it.user,messages:0,first_message_at:it.at,last_message_at:it.at};
      p.messages++;if(it.at<p.first_message_at)p.first_message_at=it.at;if(it.at>p.last_message_at)p.last_message_at=it.at;map.set(id,p);}
    return [...map.values()].sort((a,b)=>b.messages-a.messages);}

  // ---- Filters ----
  function buildFilters(){
    const counts={};for(const it of V.items)counts[it.cat]=(counts[it.cat]||0)+1;
    $("#v-cats").innerHTML=Object.entries(meta.cats).filter(([c])=>counts[c]).map(([c,label])=>'<button type="button" class="v-chip tone-'
      +(CAT[c]||["","slate"])[1]+'" data-cat="'+c+'" aria-pressed="'+V.filter.cats.has(c)+'"><i class="dot"></i>'+esc(label)+" <b>"+num(counts[c])+"</b></button>").join("");
    for(const b of $$("#v-cats [data-cat]"))b.addEventListener("click",()=>{const c=b.dataset.cat;
      V.filter.cats.has(c)?V.filter.cats.delete(c):V.filter.cats.add(c);b.setAttribute("aria-pressed",String(V.filter.cats.has(c)));apply();});
    if(!chat){const per={};for(const it of V.items)if(it.chat!=null)per[it.chat]=(per[it.chat]||0)+1;
      const list=Object.entries(per).sort((a,b)=>b[1]-a[1]);$("#v-chats-box").hidden=list.length<2;
      $("#v-chats").innerHTML=list.map(([id,n])=>'<label><input type="checkbox" value="'+esc(id)+'"><span>'+esc(title(id))+"</span><b>"+num(n)+"</b></label>").join("");
      for(const c of $$("#v-chats input"))c.addEventListener("change",()=>{c.checked?V.filter.chats.add(c.value):V.filter.chats.delete(c.value);apply();});}
    const peopleBox=$("#v-people"),peopleQ=$("#v-people-q");
    const drawPeople=()=>{const q=peopleQ.value.trim().toLowerCase();const found=V.people.filter(p=>!q||[p.name,p.username,p.user_id].join(" ").toLowerCase().includes(q)).slice(0,40);
      peopleBox.innerHTML=found.map(p=>'<label><input type="checkbox" value="'+esc(String(p.user_id??p.name))+'"'+(V.filter.people.has(String(p.user_id??p.name))?" checked":"")
        +'><span>'+esc(p.name||say("Unknown"))+(p.username?' <small>@'+esc(p.username)+"</small>":"")+"</span><b>"+num(p.messages)+"</b></label>").join("")
        +(V.people.length>40&&!q?'<div class="more">'+esc(sayf("{n} people; search to find others",{n:num(V.people.length)}))+"</div>":"");
      for(const c of $$("#v-people input"))c.addEventListener("change",()=>{c.checked?V.filter.people.add(c.value):V.filter.people.delete(c.value);apply();});};
    peopleQ.oninput=drawPeople;drawPeople();V.drawPeople=drawPeople;
    if($("#v-only").childElementCount)return;
    const only=[["link",say("With links")],["wallet",say("With wallets")],["media",say("With files")],["edited",say("Edited")],
      ...(chat?[["found",say("Found on recheck")]]:[["deleted",say("Changed or deleted messages")]]),["selected",say("Selected")]];
    $("#v-only").innerHTML=only.map(([k,label])=>'<label><span>'+esc(label)+'</span><input type="checkbox" value="'+k+'"></label>').join("");
    for(const c of $$("#v-only input"))c.addEventListener("change",()=>{c.checked?V.filter.only.add(c.value):V.filter.only.delete(c.value);apply();});}
  function bindControls(){
    let timer;$("#v-q").addEventListener("input",e=>{clearTimeout(timer);timer=setTimeout(()=>{V.filter.q=e.target.value;apply();},160);});
    $("#v-from").addEventListener("change",e=>{V.filter.from=e.target.value;apply();});$("#v-to").addEventListener("change",e=>{V.filter.to=e.target.value;apply();});
    $("#v-sort").addEventListener("change",e=>{V.filter.sort=e.target.value;apply();});
    $("#v-reset").addEventListener("click",()=>{clearTimeout(timer);V.filter.q="";V.filter.chats.clear();V.filter.people.clear();V.filter.only.clear();V.filter.keys=null;
      V.filter.from=V.filter.to="";V.filter.cats=new Set(Object.keys(meta.cats).filter(c=>!(meta.hidden||[]).includes(c)));
      $("#v-q").value=$("#v-from").value=$("#v-to").value=$("#v-people-q").value="";for(const c of $$("#v-only input,#v-chats input"))c.checked=false;
      for(const b of $$("#v-cats [data-cat]"))b.setAttribute("aria-pressed",String(V.filter.cats.has(b.dataset.cat)));V.drawPeople();apply();});
    $("#v-jump").addEventListener("keydown",e=>{if(e.key!=="Enter"||!V.results.length)return;const want=parseInt(e.target.value.replace(/\D/g,""),10);if(isNaN(want))return;
      const asc=V.filter.sort==="asc";let i=V.results.findIndex(it=>asc?it.n>=want:it.n<=want);if(i<0)i=V.results.length-1;focusRow(V.results[i].key,i);});
    $("#v-pick-all").addEventListener("click",()=>{if(V.results.length>5000&&!confirm(sayf("Select all {n} shown items?",{n:num(V.results.length)})))return;
      for(const it of V.results)V.selected.add(it.key);selectionChanged();});
    $("#v-earlier").addEventListener("click",()=>render(Math.max(0,V.from-200)));
    new IntersectionObserver(e=>{if(e.some(x=>x.isIntersecting))more();},{rootMargin:"900px"}).observe($("#v-more"));
    for(const b of $$("[data-sel]"))b.addEventListener("click",()=>selection(b.dataset.sel));}
  function terms(q){const out=[];for(const m of q.matchAll(/"([^"]+)"|(\S+)/g)){const t=(m[1]||m[2]).toLowerCase();
      if(/^#\d+$/.test(t))out.push({num:+t.slice(1)});else if(/^@\w+$/.test(t))out.push({user:t.slice(1)});else out.push({text:t});}return out;}
  function apply(){const f=V.filter,want=terms(f.q),out=[];
    for(const it of V.items){
      if(!f.cats.has(it.cat))continue;if(f.keys&&!f.keys.has(it.key))continue;
      if(f.chats.size&&!f.chats.has(String(it.chat)))continue;if(f.people.size&&!f.people.has(String(it.uid??it.who)))continue;
      const day=(it.at||"").slice(0,10);if(f.from&&day<f.from)continue;if(f.to&&day>f.to)continue;
      if(f.only.has("link")&&!it.link)continue;if(f.only.has("wallet")&&!it.wallet)continue;if(f.only.has("media")&&!it.file&&!(it.d||{}).media_info)continue;
      if(f.only.has("edited")&&!(it.edited||it.cat==="edited"))continue;if(f.only.has("found")&&!it.found)continue;
      if(f.only.has("deleted")&&!["edited","deleted"].includes(it.cat))continue;if(f.only.has("selected")&&!V.selected.has(it.key))continue;
      if(want.length&&!want.every(t=>t.num!=null?it.n===t.num:t.user?String(it.user||"").toLowerCase()===t.user:it.hay.includes(t.text)))continue;
      out.push(it);}
    if(f.sort==="desc")out.reverse();V.results=out;V.terms=want.filter(t=>t.text).map(t=>t.text);
    V.plain=f.sort==="asc"&&!f.q&&!f.people.size&&!f.keys&&!f.only.size&&!f.from&&!f.to
      &&Object.keys(meta.cats).every(c=>f.cats.has(c))&&!V.files.bad.length&&!V.files.missing.length;
    countBox.textContent=sayf("{a} of {b}",{a:num(out.length),b:num(V.items.length)});
    const active=[];if(f.keys)active.push(["keys",f.keysLabel]);for(const p of f.people){const person=V.people.find(x=>String(x.user_id??x.name)===p);active.push(["person:"+p,person?person.name:p]);}
    $("#v-active").innerHTML=active.map(([k,label])=>'<button type="button" class="v-chip on" data-off="'+esc(k)+'">'+esc(label)+" ✕</button>").join("");
    for(const b of $$("#v-active [data-off]"))b.addEventListener("click",()=>{const k=b.dataset.off;if(k==="keys")f.keys=null;else f.people.delete(k.slice(7));V.drawPeople();apply();});
    render(0);}

  // ---- The feed: rows rendered as they come into view ----
  function render(from){V.from=from;V.to=from;const list=$("#v-list");list.innerHTML="";$("#v-earlier").hidden=from===0;
    if(!V.results.length)list.innerHTML='<div class="v-empty">'+esc(say("Nothing matches these filters."))+"</div>";more();}
  function day(it){return (it&&it.at||"").slice(0,10);}
  function gapBetween(a,b){return chat&&meta.numbered&&V.plain&&a&&b&&b.n>a.n+1;}
  function together(a,b){return chat&&a&&b&&V.filter.sort==="asc"&&a.cat!=="service"&&b.cat!=="service"&&String(a.uid??a.who)===String(b.uid??b.who)
    &&day(a)===day(b)&&!gapBetween(a,b)&&Math.abs(new Date(b.at)-new Date(a.at))<10*60000;}
  function more(){if(V.to>=V.results.length)return;const list=$("#v-list"),html=[];let end=Math.min(V.results.length,V.to+150);
    for(let i=V.to;i<end;i++){const it=V.results[i],prev=V.results[i-1],next=V.results[i+1];
      if(day(it)!==day(prev))html.push('<div class="day-sep"><span>'+esc(dayOf(it.at))+"</span></div>");
      if(!chat&&meta.group_heartbeats&&it.kind==="collector.heartbeat"){
        let stop=i+1;while(stop<V.results.length&&V.results[stop].kind===it.kind&&day(V.results[stop])===day(it)
          &&Math.abs(V.results[stop].n-V.results[stop-1].n)===1)stop++;
        if(stop-i>1){html.push('<details class="v-run" data-run-start="'+i+'" data-run-end="'+stop+'"><summary>'
          +esc(sayf("Collector heartbeats: {n}",{n:num(stop-i)}))+' <small>#'+it.n+' – #'+V.results[stop-1].n
          +'</small></summary><div class="v-run-items"></div></details>');end=Math.max(end,stop);i=stop-1;continue;}}
      if(gapBetween(prev,it))html.push('<div class="gap-row"><span>'+esc(it.n-prev.n===2?sayf("Message number {n} absent",{n:prev.n+1})
          :sayf("Message numbers {a}–{b} absent ({n})",{a:prev.n+1,b:it.n-1,n:it.n-prev.n-1}))+"</span></div>");
      html.push(chat?message(it,!together(prev,it),!together(it,next)):record(it));}
    list.insertAdjacentHTML("beforeend",html.join(""));V.to=end;}
  function expandRun(group){if(group.dataset.next)return;appendRun(group);}
  function appendRun(group){const from=Number(group.dataset.next||group.dataset.runStart),stop=Math.min(Number(group.dataset.runEnd),from+150);
    group.querySelector('[data-run-more]')?.remove();
    group.querySelector('.v-run-items').insertAdjacentHTML('beforeend',V.results.slice(from,stop).map(record).join(''));
    group.dataset.next=String(stop);if(stop<Number(group.dataset.runEnd))group.querySelector('.v-run-items').insertAdjacentHTML('beforeend',
      '<button type="button" class="v-btn ghost" data-run-more>'+esc(say("Show more"))+'</button>');}
  $("#v-list").addEventListener("toggle",e=>{if(e.target.matches(".v-run")&&e.target.open)expandRun(e.target);},true);
  function hl(text){text=String(text??"");const terms=[...new Set(V.terms||[])].filter(t=>t.length>=2).sort((a,b)=>b.length-a.length);
    if(!terms.length)return esc(text);const re=new RegExp(terms.map(t=>t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")).join("|"),"gi");
    let out="",last=0;for(const m of text.matchAll(re)){out+=esc(text.slice(last,m.index))+"<mark>"+esc(m[0])+"</mark>";last=m.index+m[0].length;}
    return out+esc(text.slice(last));}
  function tags(it){const b=[];
    if(chat&&it.raw?.selection)b.push('<span class="tag blue">'+esc(say(it.raw.selection.role==="context"?"Context message":"Matches export filters"))+"</span>");
    if(it.cat==="deleted")b.push('<span class="tag red">'+esc(say("deleted"))+"</span>");
    if(it.found)b.push('<span class="tag orange">'+esc(say("found on recheck"))+"</span>");
    if(it.wallet)b.push('<span class="tag red">'+ic("tag")+esc(say("wallet"))+"</span>");else if(it.link)b.push('<span class="tag blue">'+esc(say("link"))+"</span>");
    if(((it.d||{}).text_entities||[]).some(x=>x.deceptive))b.push('<span class="tag red">⚠ '+esc(say("disguised link"))+"</span>");
    if(it.withheld)b.push('<span class="tag">'+esc(say("minimised"))+"</span>");return b.join("");}
  function pickBox(it){return '<input type="checkbox" class="pick"'+(V.selected.has(it.key)?" checked":"")+' aria-label="'+esc(say("Select"))+'">';}
  function shortText(t){return t.length>1200?t.slice(0,1200)+"…":t;}
  function message(it,first,last){
    if(it.cat==="service")return '<div class="msg-service" data-key="'+it.key+'"><span>'+esc(it.who)+" · "+esc(it.service)+" · #"+it.n+" · "+esc(clock(it.at))+"</span></div>";
    const media=meta.media_previews!==false&&it.file&&isImage(it)?'<img class="msg-img" alt="" loading="lazy" src="'+esc(it.file.path)+'">':(it.file||it.d.media_type)?
      '<div class="msg-media">'+ic("file")+"<span>"+esc(it.file&&it.file.name||(it.d.media_info||{}).file_name||say("Attachment"))+"</span></div>":"";
    return '<article class="msg '+colour(it.uid??it.who)+(first?" first":"")+(last?" last":"")+(V.selected.has(it.key)?" picked":"")+'" data-key="'+it.key+'" role="listitem" tabindex="0">'
      +pickBox(it)+'<div class="msg-ava">'+(last?'<div class="ava">'+esc(initials(it.who))+"</div>":"")+'</div><div class="msg-bubble">'
      +(first?'<div class="msg-name">'+esc(it.who)+(it.user?"<span>@"+esc(it.user)+"</span>":"")+"</div>":"")+media
      +(it.text?'<div class="msg-text" dir="auto">'+hl(shortText(it.text))+"</div>":"")
      +'<div class="msg-foot">'+tags(it)+'<span class="msg-meta">'+(it.edited?esc(say("edited"))+" · ":"")+"#"+it.n+" · "+esc(clock(it.at))+"</span></div></div></article>";}
  function record(it){const [glyph,tone]=CAT[it.cat]||CAT.system;
    const text=it.textWithheld?'<div class="rec-text v-muted">'+esc(say("Text withheld in this extract"))+"</div>":it.text?'<div class="rec-text" dir="auto">'+hl(shortText(it.text))+"</div>":
      it.p?'<div class="rec-p">'+esc(it.p.slice(0,260))+"</div>":"";
    return '<article class="rec2'+(V.selected.has(it.key)?" picked":"")+'" data-key="'+it.key+'" role="listitem" tabindex="0">'+pickBox(it)
      +'<span class="rec-icon tone-'+tone+'">'+ic(glyph)+"</span><div>"
      +'<div class="rec-top"><span class="rec-kind">'+esc(kindLabel(it))+"</span>"+(it.chat!=null?'<span class="rec-chat">'+esc(title(it.chat))+"</span>":"")
      +(it.msg!=null?"<span>"+esc(sayf("message {id}",{id:it.msg}))+"</span>":"")+'<span class="rec-time">'+esc(clockSec(it.at))+" UTC</span></div>"
      +(it.who?'<div class="rec-who">'+esc(it.who)+(it.user?" <span>@"+esc(it.user)+"</span>":"")+"</div>":"")+text
      +'<div class="rec-foot"><span class="rec-seq">#'+it.n+"</span>"+(it.file?'<span class="tag violet">'+ic("file")+esc(say("file"))+"</span>":"")+tags(it)+"</div></div></article>";}
  $("#v-list").addEventListener("click",e=>{const more=e.target.closest("[data-run-more]");if(more){appendRun(more.closest(".v-run"));return;}
    const row=e.target.closest("[data-key]");if(!row)return;const key=row.dataset.key;
    if(e.target.classList.contains("pick")){e.target.checked?V.selected.add(key):V.selected.delete(key);row.classList.toggle("picked",e.target.checked);
      selectionChanged(true);return;}detail(key);});
  $("#v-list").addEventListener("keydown",e=>{if(e.key==="Enter"&&e.target.dataset&&e.target.dataset.key)detail(e.target.dataset.key);});
  function focusRow(key,index){render(Math.max(0,index-3));for(const group of $$("#v-list .v-run")){
      if(Number(group.dataset.runStart)<=index&&index<Number(group.dataset.runEnd)){expandRun(group);group.open=true;}}
    const row=$('#v-list [data-key="'+key+'"]');
    if(row){row.scrollIntoView({block:"center"});row.animate([{background:"color-mix(in srgb,#f5c542 35%,transparent)"},{background:"transparent"}],{duration:1600});}}

  // ---- One item in full ----
  function detail(key){const it=V.byKey.get(key);if(!it)return;const d=it.d||{},box=$("#v-detail"),facts=[];
    for(const r of $$("#v-list .open"))r.classList.remove("open");const shown=$('#v-list [data-key="'+key+'"]');if(shown)shown.classList.add("open");
    const fact=(k,v)=>{if(v!==undefined&&v!==null&&v!=="")facts.push("<dt>"+esc(k)+"</dt><dd>"+v+"</dd>");};
    fact(chat?say("Sent"):say("Observed"),esc(when(it.at)));
    if(!chat&&it.sent)fact(say("Sent"),esc(when(it.sent)));
    if(it.chat!=null)fact(say("Chat"),esc(title(it.chat))+"<br><small>id "+esc(it.chat)+"</small>");if(it.msg!=null)fact(say("Message"),"#"+esc(it.msg));
    if(chat)fact(say("Message"),"#"+esc(it.n));
    if(it.who&&!chat)fact(say("Sender"),esc(it.who)+(it.user?" @"+esc(it.user):"")+(it.uid!=null?"<br><small>ID "+esc(it.uid)+"</small>":""));
    if(it.edited)fact(say("Edited"),esc(when(it.edited))+(chat?"<br><small>"+esc(say("earlier text not in this export"))+"</small>":""));
    const replyChat=Number.isSafeInteger(d.reply_to_peer_id)?d.reply_to_peer_id:it.chat;
    if(Number.isSafeInteger(d.reply_to_message_id)){const reply=chat?(replyChat==null||replyChat===meta.chat_id?V.byKey.get("m"+d.reply_to_message_id):null)
      :V.items.find(x=>x.chat===replyChat&&x.msg===d.reply_to_message_id&&["message","edited"].includes(x.cat));
      fact(say("Reply to"),reply?'<a href="#" data-goto="'+esc(reply.key)+'">#'+esc(d.reply_to_message_id)+"</a>":"#"+esc(d.reply_to_message_id));}
    if(Number.isSafeInteger(d.reply_to_peer_id))fact(say("Chat of the original message"),esc(d.reply_to_peer_id));
    if(Number.isSafeInteger(d.reply_to_top_id))fact(say("Reply thread"),"#"+esc(d.reply_to_top_id));
    if(typeof d.forum_topic==="boolean")fact(say("Forum topic"),esc(d.forum_topic?say("Yes"):say("No")));
    if(typeof d.quote_text==="string"&&d.quote_text){fact(say("Quoted text"),esc(d.quote_text));
      if(Number.isSafeInteger(d.quote_offset))fact(say("Quote offset (UTF-16)"),esc(d.quote_offset));}
    const fwd=d.forwarded_from;if(fwd)fact(say("Forwarded from"),esc(fwd.from_name||(fwd.from_id!=null?"ID "+fwd.from_id:say("a hidden sender")))
      +(fwd.date?"<br><small>"+esc(when(fwd.date))+(fwd.channel_post?" · #"+esc(fwd.channel_post):"")+"</small>":""));
    if(d.via_bot_id!=null)fact(say("Via bot"),"ID "+esc(d.via_bot_id));if(d.author)fact(say("Signed"),esc(d.author));
    const counts=[["views",say("views")],["forwards",say("forwards")],["replies",say("replies")]].filter(([k])=>typeof d[k]==="number").map(([k,l])=>num(d[k])+" "+l);
    if(d.reactions&&d.reactions.length)counts.push(d.reactions.map(r=>r.reaction+" "+num(r.count)).join("  "));if(counts.length)fact(say("Reach"),esc(counts.join(" · ")));
    if(typeof d.auto_delete_seconds==="number")fact(say("Auto-delete timer"),esc(span(d.auto_delete_seconds)));
    if(d.protected)fact(say("Protected"),esc(say("saving and forwarding restricted")));if(it.withheld)fact(say("Minimised"),esc(it.withheld.join(", ")));
    if(it.file)fact(say("File"),esc(it.file.name||say("Saved file"))+(it.file.size?" · "+num(it.file.size)+" B":"")+'<br><small><code>'+esc(it.file.sha)+"</code></small>");
    else if(d.media_type)fact(say("File"),esc(d.media_type)+(d.file_status?"<br><small>"+esc(d.file_status)+"</small>":""));
    const links=[...(d.text_entities||[]),...(d.quote_entities||[])].filter(x=>x.href||x.user_id!=null).map(x=>"<li"+(x.deceptive?' class="warn"':"")+">“"+esc(x.text)+"” → <code>"
      +esc(x.href||"user ID "+x.user_id)+"</code>"+(x.deceptive?'<br><b>⚠ '+esc(say("the text shows a different address"))+"</b>":"")+"</li>").join("");
    const buttons=((d.buttons&&d.buttons.rows)||[]).flat().map(b=>"<span>"+esc(b.text)+(b.url||b.query||b.copy_text?"<code>"+esc(b.url||b.query||b.copy_text)+"</code>":"")+"</span>").join("");
    const iocs=(V.iocKeys.get(key)||[]).map(i=>V.iocs[i]).map(x=>"<li><b>"+esc((meta.iocKinds||{})[x.kind]||x.kind)+"</b> · <code>"+esc(defang(x.kind,x.value))+"</code>"
      +(x.chain?" · "+esc(x.chain):"")+"</li>").join("");
    let history="";if(!chat&&it.msg!=null&&it.chat!=null){const same=V.items.filter(x=>x.chat===it.chat&&x.msg===it.msg&&x!==it);
      if(same.length)history='<div class="d-section"><h4>'+ic("layers")+esc(say("Other records of this message"))+'</h4><ul class="d-hist">'
        +same.map(x=>'<li><a href="#" data-goto="'+x.key+'">#'+x.n+"</a> · "+esc(kindLabel(x))+" · "+esc(when(x.at))+(x.text?"<div>"+esc(x.text.slice(0,300))+"</div>":"")+"</li>").join("")+"</ul></div>";}
    const proof=chat?esc(sayf("Message #{n} of chat.json; the archive's manifest signs chat.json (SHA-256 {hash}).",{n:it.n,hash:String(meta.data_sha256||"").slice(0,16)+"…"}))
      :esc(say("Record hash"))+'<br><code>'+esc(it.hash)+"</code><br>"+esc(say("Each record is signed when it is captured; verify.py checks the record, its signature and its place in the chain."));
    const [glyph,tone]=CAT[it.cat]||CAT.system;
    const head=chat?'<div class="ava '+colour(it.uid??it.who)+'">'+esc(initials(it.who))+"</div><div><b>"+esc(it.who)+"</b><small>"+(it.user?"@"+esc(it.user)+" · ":"")
      +(it.uid!=null?"ID "+esc(it.uid):"")+"</small></div>":'<span class="rec-icon tone-'+tone+'">'+ic(glyph)+"</span><div><b>"+esc(kindLabel(it))+" · #"+it.n+"</b><small>"+esc(when(it.at))+"</small></div>";
    box.innerHTML='<div class="d-head">'+head+'<button type="button" class="d-close" data-close aria-label="'+esc(say("Close"))+'">'+ic("x")+'</button></div><div class="d-body">'
      +(it.textWithheld?'<div class="d-text v-muted">'+esc(say("Text withheld in this extract"))+"</div>":it.text?'<div class="d-text" dir="auto">'+hl(it.text)+"</div>":it.service?'<div class="d-text" dir="auto">'+esc(it.service)+"</div>"
        :it.p?'<div class="d-text rec-p">'+esc(it.p)+"</div>":"")
      +(meta.media_previews!==false&&it.file&&isImage(it)?'<img class="d-img" alt="" loading="lazy" src="'+esc(it.file.path)+'">':"")
      +(links?'<div class="d-section"><h4>'+ic("route")+esc(say("Links behind the text"))+'</h4><ul class="d-links">'+links+"</ul></div>":"")
      +(buttons?'<div class="d-section"><h4>'+ic("key")+esc(say("Buttons"))+'</h4><div class="d-keys">'+buttons+"</div></div>":"")
      +'<div class="d-section"><h4>'+ic("info")+esc(say("Details"))+'</h4><dl class="d-list">'+facts.join("")+"</dl></div>"
      +(iocs?'<div class="d-section"><h4>'+ic("tag")+esc(say("Indicators in this item"))+'</h4><ul class="d-links">'+iocs+"</ul></div>":"")+history
      +'<div class="d-proof">'+ic("shield")+"<div>"+proof+"</div></div>"
      +(!chat&&meta.raw_records&&it.raw.r?'<details class="d-section d-raw"><summary>'+esc(say("Full record data"))
        +'</summary><pre><code>'+esc(JSON.stringify(it.raw.r,null,2))+'</code></pre></details>':"")
      +'<div class="d-actions"><button type="button" class="v-btn" data-pick>'+esc(V.selected.has(key)?say("Unselect"):say("Select"))
      +'</button><button type="button" class="v-btn ghost" data-copy>'+ic("copy")+esc(say("Copy text"))+'</button><button type="button" class="v-btn ghost" data-ref>'
      +esc(say("Copy reference"))+"</button></div></div>";
    box.hidden=false;box.scrollTop=0;box.setAttribute("tabindex","-1");box.setAttribute("aria-label",say("Details"));box.focus({preventScroll:true});
    box.querySelector("[data-close]").onclick=()=>{box.hidden=true;if(shown){shown.classList.remove("open");shown.focus({preventScroll:true});}};
    box.onkeydown=e=>{if(e.key==="Escape"){e.preventDefault();box.querySelector("[data-close]").click();}};
    box.querySelector("[data-pick]").onclick=()=>{V.selected.has(key)?V.selected.delete(key):V.selected.add(key);selectionChanged();detail(key);};
    box.querySelector("[data-copy]").onclick=()=>navigator.clipboard&&navigator.clipboard.writeText(it.text||"");
    box.querySelector("[data-ref]").onclick=()=>navigator.clipboard&&navigator.clipboard.writeText(reference(it));}
  function goto(key){if(!V.byKey.has(key))return;let i=V.results.findIndex(x=>x.key===key);
    if(i<0){$("#v-reset").click();i=V.results.findIndex(x=>x.key===key);}if(i<0)return detail(key);focusRow(key,i);detail(key);}
  function reference(it){return (meta.report_id?"TgWitness "+meta.report_id+" · ":"")+(chat?(meta.chat_title||"")+" #"+it.n:"#"+it.n+" "+it.kind+(it.hash?" "+it.hash:""))+" · "+(it.at||"");}

  // ---- Selection: print, a verifiable extract, a spreadsheet ----
  function selectionChanged(quiet){const n=V.selected.size;$("#v-selbar").hidden=!n;$("#v-selcount").textContent=sayf("{n} selected",{n:num(n)});
    $("#v-list").classList.toggle("selecting",n>0);
    if(!quiet)for(const c of $$("#v-list .pick")){const row=c.closest("[data-key]");c.checked=V.selected.has(row.dataset.key);row.classList.toggle("picked",c.checked);}}
  function picked(){return V.items.filter(it=>V.selected.has(it.key));}
  function selection(action){const items=picked();
    if(action==="clear"){V.selected.clear();selectionChanged();if(V.filter.only.has("selected"))apply();return;}
    if(action==="only"){V.filter.only.add("selected");const box=$('#v-only input[value="selected"]');if(box)box.checked=true;apply();return;}
    const stem="tgwitness-selection-"+String(meta.report_id||"").slice(0,8);
    if(action==="json"){save(stem+".json",JSON.stringify({format:"tgwitness-selection-v1",made_at:new Date().toISOString(),
      made_with:"TgWitness report viewer",note:say("Items chosen in the report viewer. verify.py checks each against the signed archive: python verify.py THIS_FILE --evidence ARCHIVE"),
      source:{kind:meta.kind,report_id:meta.report_id,fingerprint:meta.fingerprint,archive:meta.archive,chat_id:meta.chat_id,
        chat_json_sha256:meta.data_sha256,head_hash:meta.head_hash,event_count:meta.event_count},
      items:chat?items.map(it=>it.raw):items.map(it=>({seq:it.n,hash:it.hash,kind:it.kind,observed_at:it.at,chat_id:it.chat??null,
        message_id:it.msg??null,sender_id:it.uid??null,text:it.text||null}))},null,1),"application/json");return;}
    if(action==="csv"){const cols=["number","time","chat","sender","username","sender_id","text","edited","file_sha256","record_hash"];
      const cell=v=>{let s=String(v??"");if(/^[=+\-@\t\r]/.test(s))s="'"+s;return /[",\n\r]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;};
      save(stem+".csv","\ufeff"+[cols.join(",")].concat(items.map(it=>[it.n,it.at,chat?meta.chat_title:title(it.chat),it.who,it.user,it.uid,it.text,it.edited,
        it.file&&it.file.sha,it.hash].map(cell).join(","))).join("\r\n"),"text/csv");return;}
    if(action==="print"){const sheet=$("#print-sheet");sheet.innerHTML="<h1>"+esc(meta.title||"")+"</h1><p>"+esc(sayf("{n} items chosen from report {id}, key {fp}",
      {n:items.length,id:meta.report_id||"",fp:meta.fingerprint||""}))+"</p>"+items.map(it=>'<div class="p-item"><div class="p-head">#'+it.n+" · "+esc(when(it.at))
      +(chat?"":" · "+esc(kindLabel(it))+(it.chat!=null?" · "+esc(title(it.chat)):""))+(it.who?" · "+esc(it.who)+(it.user?" @"+esc(it.user):"")
      +(it.uid!=null?" · ID "+esc(it.uid):""):"")+"</div>"+(it.text?'<div class="p-text" dir="auto">'+esc(it.text)+"</div>":"")+(it.hash?'<div class="p-hash">'+esc(it.hash)+"</div>":"")
      +"</div>").join("")+'<p class="p-note">'+esc(say("Check this list against the signed archive with verify.py and the extract saved as JSON."))+"</p>";
      document.body.classList.add("printing-selection");const done=()=>{document.body.classList.remove("printing-selection");window.removeEventListener("afterprint",done);};
      window.addEventListener("afterprint",done);print();}}

  // ---- People ----
  function buildPeople(){const box=$("#view-people");if(!box)return;
    box.innerHTML='<div class="v-page"><div class="v-page-head"><h2>'+esc(chat?say("Participants"):say("Senders"))+'</h2><input type="search" id="p-q" placeholder="'
      +esc(say("Name, @username or ID"))+'"></div><div class="v-table"><table id="p-table"><thead><tr><th>'+esc(say("Person"))+"</th><th>ID</th><th>"
      +esc(say("Messages"))+"</th><th>"+esc(say("First message"))+"</th><th>"+esc(say("Last message"))+'</th><th></th></tr></thead><tbody></tbody></table></div><p class="v-muted" id="p-more"></p></div>';
    const draw=()=>{const q=$("#p-q").value.trim().toLowerCase();const list=V.people.filter(p=>!q||[p.name,p.username,p.user_id].join(" ").toLowerCase().includes(q));
      $("#p-table tbody").innerHTML=list.slice(0,500).map(p=>'<tr><td><div class="person"><span class="ava '+colour(p.user_id??p.name)+'">'+esc(initials(p.name))+"</span><div><b>"
        +esc(p.name||say("Unknown"))+"</b><small>"+(p.username?"@"+esc(p.username):"")+((p.signatures||[]).length?" · "+esc(sayf("Signed by: {names}",{names:p.signatures.join(", ")})):"")
        +"</small></div></div></td><td><code>"+esc(p.user_id)+"</code></td><td><b>"+num(p.messages)+'</b></td><td class="t">'+esc(when(p.first_message_at))+'</td><td class="t">'+esc(when(p.last_message_at))
        +'</td><td><button type="button" class="v-btn ghost" data-person="'+esc(String(p.user_id??p.name))+'">'+ic("message")+esc(say("Messages"))+"</button></td></tr>").join("");
      $("#p-more").textContent=list.length>500?sayf("{n} more: search to narrow the list",{n:num(list.length-500)}):"";
      for(const b of $$("#p-table [data-person]"))b.addEventListener("click",()=>{$("#v-reset").click();V.filter.people=new Set([b.dataset.person]);V.drawPeople();apply();show("data");});};
    $("#p-q").addEventListener("input",draw);draw();
    for(const t of tabs)if(t.dataset.view==="people")t.querySelector("b").textContent=num(V.people.length);}

  // ---- Indicators ----
  function buildIocs(){const box=$("#view-iocs");if(!box)return;const kinds={};for(const x of V.iocs)kinds[x.kind]=(kinds[x.kind]||0)+1;const on=new Set(Object.keys(kinds));
    box.innerHTML='<div class="v-page"><div class="v-page-head"><h2>'+esc(say("Indicators"))+'</h2><input type="search" id="i-q" placeholder="'+esc(say("Search indicators"))+'"></div>'
      +'<p class="lead">'+esc(meta.iocLead||"")+'</p><div class="v-chips" id="i-kinds">'+Object.entries(kinds).map(([k,n])=>'<button type="button" class="v-chip" aria-pressed="true" data-kind="'+k+'">'
      +esc((meta.iocKinds||{})[k]||k)+" <b>"+num(n)+"</b></button>").join("")+'</div><div class="v-table"><table id="i-table"><thead><tr><th>'+esc(say("Type"))+"</th><th>"
      +esc(say("Value"))+"</th><th>"+esc(say("Seen"))+"</th><th>"+esc(say("Where in the message"))+"</th><th>"+esc(say("First seen"))+'</th><th></th></tr></thead><tbody></tbody></table></div><p class="v-muted" id="i-more"></p></div>';
    const draw=()=>{const q=$("#i-q").value.trim().toLowerCase();const list=V.iocs.map((x,i)=>[x,i]).filter(([x])=>on.has(x.kind)&&(!q||String(x.value).toLowerCase().includes(q)));
      $("#i-table tbody").innerHTML=list.slice(0,1000).map(([x,i])=>"<tr><td><b>"+esc((meta.iocKinds||{})[x.kind]||x.kind)+"</b>"+(x.chain?"<br><small>"+esc(x.chain)+" · "+esc(x.checksum||"")+"</small>":"")
        +"</td><td><code>"+esc(defang(x.kind,x.value))+"</code>"+(x.dhash?"<br><small>dHash "+esc(x.dhash)+"</small>":"")+'<br><button type="button" class="v-link" data-copy-ioc="'+i+'">'+esc(say("Copy as is"))
        +"</button></td><td><b>"+num(x.count)+"</b></td><td>"+esc((x.sources||[]).join(", "))+'</td><td class="t">'+esc(when(x.first_seen))+'</td><td><button type="button" class="v-btn ghost" data-ioc="'+i+'">'
        +ic("message")+esc(say("Messages"))+"</button></td></tr>").join("");
      $("#i-more").textContent=list.length>1000?sayf("{n} more: search to narrow the list",{n:num(list.length-1000)}):"";
      for(const b of $$("#i-table [data-ioc]"))b.addEventListener("click",()=>{$("#v-reset").click();const x=V.iocs[+b.dataset.ioc];V.filter.keys=new Set((x.refs||[]).map(refKey).filter(Boolean));
        V.filter.keysLabel=((meta.iocKinds||{})[x.kind]||x.kind)+": "+defang(x.kind,x.value);V.filter.cats=new Set(Object.keys(meta.cats));
        for(const c of $$("#v-cats [data-cat]"))c.setAttribute("aria-pressed","true");apply();show("data");});
      for(const b of $$("#i-table [data-copy-ioc]"))b.addEventListener("click",()=>navigator.clipboard&&navigator.clipboard.writeText(String(V.iocs[+b.dataset.copyIoc].value)));};
    for(const b of $$("#i-kinds [data-kind]"))b.addEventListener("click",()=>{const k=b.dataset.kind;on.has(k)?on.delete(k):on.add(k);b.setAttribute("aria-pressed",String(on.has(k)));draw();});
    $("#i-q").addEventListener("input",draw);draw();
    for(const t of tabs)if(t.dataset.view==="iocs"){t.querySelector("b").textContent=num(V.iocs.length);t.hidden=!V.iocs.length;}}

  function buildCheck(){const box=$("#view-check");if(!box)return;const bad=V.files.bad,missing=V.files.missing;
    box.innerHTML='<div class="v-page"><div class="v-page-head"><h2>'+esc(say("Check"))+'</h2></div><div class="v-cards">'
      +card(sealOk?"ok":"warn","shield",sealOk?"green":"orange",say("Digital signature"),sealOk?say("The seal's Ed25519 signature is valid and names the key shown in the title."):say("The seal signature could not be checked in this browser"))
      +card(bad.length?"bad":missing.length||!sealOk?"warn":"ok","layers",bad.length?"red":missing.length||!sealOk?"orange":"green",say("Data shown here"),bad.length?sayf("{n} data files do not match the seal and are not shown",{n:bad.length})+": "+bad.join(", ")
        :missing.length?sayf("{n} data files were not found next to this page",{n:missing.length}):!sealOk?say("The seal signature could not be checked in this browser"):sayf("{n} data files match the signed seal",{n:V.files.ok}))
      +card("","file","blue",say("This page"),say("A browser does not give a page its own bytes. Check the whole archive below, or drop report.html into the seal check of the Report tab."))
      +'</div><h3>'+esc(say("Check every file of the archive"))+'</h3><p class="lead">'+esc(say("Choose the archive as it was handed over (ZIP) or its unpacked folder. The manifest's signature and the SHA-256 of every file are checked here; nothing is uploaded."))
      +'</p><div class="d-actions"><label class="v-btn">'+ic("zip")+esc(say("Choose the ZIP"))+'<input type="file" id="c-zip" accept=".zip,application/zip" hidden></label>'
      +'<label class="v-btn ghost">'+ic("files")+esc(say("Choose the folder"))+'<input type="file" id="c-dir" webkitdirectory multiple hidden></label></div><div id="c-out">'+(V.checked||"")+"</div>"
      +'<h3>'+esc(say("With verify.py"))+'</h3><pre class="cmd"><code>python verify.py '+esc(meta.archive||"ARCHIVE.zip")+" --fingerprint "+esc(meta.fingerprint||"")+"</code></pre></div>";
    $("#c-zip").addEventListener("change",e=>e.target.files[0]&&fullCheck(zipSource(e.target.files[0]),e.target.files[0].name));
    $("#c-dir").addEventListener("change",e=>e.target.files.length&&fullCheck(folderSource(e.target.files),"folder"));
    for(const t of tabs)if(t.dataset.view==="check")t.classList.toggle("bad",!!bad.length);}
  function card(state,glyph,tone,heading,text){return '<div class="v-card '+state+'"><span class="rec-icon tone-'+tone+'">'+ic(glyph)+"</span><div><b>"+esc(heading)+"</b><span>"+esc(text)+"</span></div></div>";}
  async function fullCheck(source,name){if(V.checking)return;V.checking=true;
    for(const input of $$("#c-zip,#c-dir"))input.disabled=true;
    const out=$("#c-out");out.setAttribute("role","status");out.innerHTML='<div class="callout info">'+esc(say("Checking…"))+"</div>";
    try{const manifestBytes=await source.bytes("manifest.json"),sigText=await source.text("manifest.sig");
      if(!manifestBytes||!sigText)throw new Error(say("manifest.json or manifest.sig is missing"));
      const manifest=JSON.parse(new TextDecoder().decode(manifestBytes));
      const key=await crypto.subtle.importKey("raw",bytes(manifest.public_key),{name:"Ed25519"},false,["verify"]);
      const signed=await crypto.subtle.verify({name:"Ed25519"},key,bytes(sigText.trim()),manifestBytes);
      if(!signed)throw new Error(say("Manifest signature NOT valid."));
      const fp=await sha(bytes(manifest.public_key)),same=fp===meta.fingerprint;
      const names=Object.keys(manifest.files||{}),wrong=[],absent=[];let done=0;
      if(!names.length||names.some(n=>!safeName(n)||!/^([a-f0-9]{64})$/.test(manifest.files[n])))throw new Error(say("Invalid file inventory."));
      if(!same||!manifest.report||manifest.report.id!==meta.report_id)throw new Error(say("This archive belongs to a different report or signing key."));
      for(const file of names){const data=await source.bytes(file);done++;if(done%5===0||done===names.length)
        out.innerHTML='<div class="callout info">'+esc(sayf("Checking files: {a} of {b}",{a:done,b:names.length}))+"</div>";
        if(!data){absent.push(file);continue;}if(await sha(data)!==manifest.files[file])wrong.push(file);}
      const extra=(await source.list()).filter(n=>!names.includes(n)&&!["manifest.json","manifest.sig"].includes(n));
      const good=signed&&same&&!wrong.length&&!absent.length&&!extra.length;
      out.innerHTML='<div class="callout '+(good?"ok":"bad")+'"><b>'+esc(good?sayf("All {n} files match the signed manifest.",{n:names.length}):say("The archive does not match its signed manifest."))+"</b><ul>"
        +"<li>"+esc(signed?say("Manifest signature valid (Ed25519)."):say("Manifest signature NOT valid."))+"</li>"
        +"<li>"+esc(same?say("Signed by the key of this report."):sayf("Signed by a different key: {fp}",{fp}))+"</li>"
        +(wrong.length?"<li>"+esc(sayf("Changed: {list}",{list:wrong.slice(0,30).join(", ")}))+"</li>":"")
        +(absent.length?"<li>"+esc(sayf("Missing: {list}",{list:absent.slice(0,30).join(", ")}))+"</li>":"")
        +(extra.length?"<li>"+esc(sayf("Not in the manifest (not covered by the signature): {list}",{list:extra.slice(0,30).join(", ")}))+"</li>":"")
        +"</ul><small>"+esc(sayf("Checked {name} in this browser at {time}.",{name,time:new Date().toISOString()}))+"</small></div>";
      V.checked=out.innerHTML;
      if(good&&V.files.missing.length){V.source=source.chunkText;const again=descriptor.files.filter(f=>V.files.missing.includes(f.file));V.files.missing=[];
        await loadAll(again);finish();}}
    catch(e){out.innerHTML='<div class="callout bad">'+esc(e&&e.message?e.message:String(e))+"</div>";V.checked=out.innerHTML;}
    finally{V.checking=false;for(const input of $$("#c-zip,#c-dir")){input.disabled=false;input.value="";}}}

  const MAX_FILE=256*1024*1024,MAX_TOTAL=4*1024**3;
  function safeName(name){return typeof name==="string"&&name.length>0&&!/[\\\x00-\x1f\x7f:]/.test(name)
    &&!name.startsWith("/")&&name.split("/").every(p=>p&&p!=="."&&p!=="..");}
  function sizeLimit(size){if(!Number.isSafeInteger(size)||size<0||size>MAX_FILE)throw new Error(say("This file exceeds the browser's 256 MiB limit. Use verify.py for large archives."));}
  function folderSource(files){const map=new Map();for(const f of files){const parts=(f.webkitRelativePath||f.name).split("/");map.set(parts.length>1?parts.slice(1).join("/"):parts[0],f);}
    const bytesOf=async n=>{if(!map.has(n))return null;sizeLimit(map.get(n).size);return new Uint8Array(await map.get(n).arrayBuffer());};
    return {bytes:bytesOf,text:async n=>{const b=await bytesOf(n);return b&&new TextDecoder().decode(b);},list:async()=>[...map.keys()],
      chunkText:async n=>{const b=await bytesOf(n);return b&&new TextDecoder().decode(b);}};}
  function zipSource(file){let index=null;
    const invalid=()=>new Error(say("Invalid or ambiguous ZIP structure. Use verify.py to inspect the archive."));
    const slice=async(a,b)=>{if(!Number.isSafeInteger(a)||!Number.isSafeInteger(b)||a<0||b<a||b>file.size)throw invalid();
      return new Uint8Array(await file.slice(a,b).arrayBuffer());};
    const u16=(b,o)=>b[o]|b[o+1]<<8,u32=(b,o)=>(b[o]|b[o+1]<<8|b[o+2]<<16|b[o+3]<<24)>>>0,u64=(b,o)=>u32(b,o)+u32(b,o+4)*4294967296;
    async function entries(){if(index)return index;const found=new Map(),tail=await slice(Math.max(0,file.size-66000),file.size);let at=-1;
      for(let i=tail.length-22;i>=0;i--)if(u32(tail,i)===0x06054b50&&i+22+u16(tail,i+20)===tail.length){at=i;break;}if(at<0)throw new Error(say("Not a ZIP archive"));
      if(u16(tail,at+4)||u16(tail,at+6)||u16(tail,at+8)!==u16(tail,at+10))throw invalid();
      let count=u16(tail,at+10),size=u32(tail,at+12),offset=u32(tail,at+16);
      if(at>=20&&u32(tail,at-20)===0x07064b50){const z=await slice(u64(tail,at-20+8),u64(tail,at-20+8)+56);
        if(u32(z,0)!==0x06064b50||u32(z,16)||u32(z,20)||u64(z,24)!==u64(z,32))throw invalid();count=u64(z,32);size=u64(z,40);offset=u64(z,48);}
      if(!Number.isSafeInteger(count)||count>100000||size>32*1024*1024)throw invalid();
      const dir=await slice(offset,offset+size);let p=0,total=0;const seen=new Set();
      for(let n=0;n<count;n++){if(p+46>dir.length||u32(dir,p)!==0x02014b50)throw invalid();const flags=u16(dir,p+8),method=u16(dir,p+10),nameLen=u16(dir,p+28),extraLen=u16(dir,p+30),commentLen=u16(dir,p+32);
        if(flags&1)throw new Error(say("Encrypted ZIP: decrypt it before checking, or use verify.py."));
        if(u16(dir,p+34)||p+46+nameLen+extraLen+commentLen>dir.length)throw invalid();
        let csize=u32(dir,p+20),usize=u32(dir,p+24),local=u32(dir,p+42);const name=new TextDecoder().decode(dir.subarray(p+46,p+46+nameLen));
        let e=p+46+nameLen;const end=e+extraLen;while(e+4<=end){const id=u16(dir,e),len=u16(dir,e+2);if(e+4+len>end)throw invalid();if(id===1){let q=e+4;
            const take=()=>{if(q+8>e+4+len)throw invalid();const v=u64(dir,q);q+=8;return v;};
            if(usize===0xFFFFFFFF)usize=take();if(csize===0xFFFFFFFF)csize=take();if(local===0xFFFFFFFF)local=take();}e+=4+len;}
        const directory=name.endsWith("/"),clean=directory?name.slice(0,-1):name;
        if(!safeName(clean)||seen.has(clean)||e!==end)throw invalid();seen.add(clean);
        if(!Number.isSafeInteger(usize)||!Number.isSafeInteger(csize)||!Number.isSafeInteger(local)||local<0||local+30+csize>offset)throw invalid();
        total+=usize;if(total>MAX_TOTAL)throw new Error(say("This archive exceeds the browser's 4 GiB limit. Use verify.py for large archives."));
        if(!directory)found.set(name,{method,csize,usize,local,flags,dir:offset});p=end+commentLen;}
      if(p!==dir.length)throw invalid();index=found;return index;}
    async function bytesOf(name){const map=await entries(),en=map.get(name);if(!en)return null;const h=await slice(en.local,en.local+30);
      sizeLimit(en.usize);sizeLimit(en.csize);if(u32(h,0)!==0x04034b50||u16(h,6)!==en.flags||u16(h,8)!==en.method)throw invalid();
      const start=en.local+30+u16(h,26)+u16(h,28);if(start+en.csize>en.dir)throw invalid();
      if(new TextDecoder().decode(await slice(en.local+30,en.local+30+u16(h,26)))!==name)throw invalid();
      const raw=file.slice(start,start+en.csize);
      if(en.method===0){if(en.csize!==en.usize)throw invalid();return new Uint8Array(await raw.arrayBuffer());}
      if(en.method!==8)throw new Error(sayf("Unsupported compression in {name}",{name}));
      const reader=raw.stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader(),chunks=[];let length=0;
      try{for(;;){const {value,done}=await reader.read();if(done)break;length+=value.length;
          if(length>en.usize||length>MAX_FILE){await reader.cancel();throw invalid();}chunks.push(value);}}
      finally{reader.releaseLock();}if(length!==en.usize)throw invalid();const result=new Uint8Array(length);let pos=0;
      for(const chunk of chunks){result.set(chunk,pos);pos+=chunk.length;}return result;}
    return {bytes:bytesOf,text:async n=>{const b=await bytesOf(n);return b&&new TextDecoder().decode(b);},list:async()=>[...(await entries()).keys()],
      chunkText:async n=>{const b=await bytesOf(n);return b&&new TextDecoder().decode(b);}};}
}
