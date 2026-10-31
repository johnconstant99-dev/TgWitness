/* Saved content is text, including links and button data. Nothing here executes it. */
(() => {
  const n=(tag,cls,text)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;};
  const words=text=>String(text??"").match(/[\p{L}\p{N}_]+|\s+|[^\p{L}\p{N}_\s]/gu)||[];
  function diff(before,after){
    const a=words(before),b=words(after),out=[];
    let start=0,endA=a.length,endB=b.length;
    while(start<endA&&start<endB&&a[start]===b[start])start++;
    while(endA>start&&endB>start&&a[endA-1]===b[endB-1]){endA--;endB--;}
    if(start)out.push(["",a.slice(0,start).join("")]);
    const x=a.slice(start,endA),y=b.slice(start,endB);
    // Cap memory/work for pasted logs and very long posts; unchanged edges stay precise.
    if(x.length*y.length>250000){
      if(x.length)out.push(["del",x.join("")]);if(y.length)out.push(["ins",y.join("")]);
    }else{
      const width=y.length+1,table=new Uint16Array((x.length+1)*width);
      for(let i=x.length-1;i>=0;i--)for(let j=y.length-1;j>=0;j--)
        table[i*width+j]=x[i]===y[j]?table[(i+1)*width+j+1]+1:Math.max(table[(i+1)*width+j],table[i*width+j+1]);
      let i=0,j=0;
      const add=(kind,text)=>{if(out.at(-1)?.[0]===kind)out.at(-1)[1]+=text;else out.push([kind,text]);};
      while(i<x.length||j<y.length){
        if(i<x.length&&j<y.length&&x[i]===y[j]){add("",x[i++]);j++;}
        else if(j<y.length&&(i===x.length||table[i*width+j+1]>table[(i+1)*width+j]))add("ins",y[j++]);
        else add("del",x[i++]);
      }
    }
    if(endA<a.length)out.push(["",a.slice(endA).join("")]);
    return out;
  }
  function destinationData(payload){
    const entities=(payload.entities||payload.raw?.entities||[]).filter(e=>e.url||e.user_id||e.user?.id)
      .map(e=>String(payload.text||"").slice(e.offset||0,(e.offset||0)+(e.length||0))+" ["+(e.offset||0)+":"+(e.length||0)+"] → "+(e.url||"user:"+(e.user_id||e.user.id)));
    const keyboard=payload.buttons||payload.raw?.reply_markup;
    const buttons=(keyboard?.rows||[]).flatMap(row=>(Array.isArray(row)?row:row.buttons||[]).map(button=>{
      const details=typeof button.type==="object"&&button.type?button.type:button;
      const target=details.url||details.data||details.data_base64||details.callback_data||details.copy_text||details.query||details.text_to_copy||details.user_id||"";
      const kind=typeof button.type==="string"?button.type:details._||button._||"";
      return (button.text||button.label||"")+(kind?" ["+kind+"]":"")+" → "+(typeof target==="object"?JSON.stringify(target):target);
    }));
    return {entities,buttons};
  }
  function compare(before,after,tr){
    const wrap=n("section","review-diff"),tabs=n("div","review-tabs"),body=n("div","review-diff-body");
    const modes=[["inline","Inline diff"],["split","Side by side"],["raw","Raw"]];
    tabs.setAttribute("role","group");tabs.setAttribute("aria-label",tr("Compare versions"));
    const render=mode=>{
      body.replaceChildren();body.classList.toggle("review-split",mode==="split");
      for(const button of tabs.children)button.setAttribute("aria-pressed",String(button.dataset.mode===mode));
      if(mode==="inline"){
        const text=n("div","review-diff-text");
        for(const [kind,value] of diff(before.text,after.text))text.append(kind?n(kind,"diff-"+kind,value):document.createTextNode(value));
        body.append(text);
      }else for(const [label,payload] of [["Previously observed",before],["Newly observed version",after]]){
        const column=n("div");column.append(n("small","",tr(label)),n("pre","",mode==="raw"?JSON.stringify(payload,null,2):payload.text||tr("(no text)")));body.append(column);
      }
    };
    for(const [mode,label] of modes){const button=n("button","quiet small",tr(label));button.type="button";button.dataset.mode=mode;button.addEventListener("click",()=>render(mode));tabs.append(button);}
    wrap.append(tabs,body);render("inline");
    const old=destinationData(before),next=destinationData(after);
    for(const key of ["entities","buttons"]){
      if(JSON.stringify(old[key])===JSON.stringify(next[key]))continue;
      const alert=n("details","review-link-change");alert.open=true;
      alert.append(n("summary","",tr(key==="entities"?"Hidden links changed":"Buttons changed")));
      const text=n("div","review-diff-text");
      for(const [kind,value] of diff(old[key].join("\n"),next[key].join("\n")))
        text.append(kind?n(kind,"diff-"+kind,value):document.createTextNode(value));
      alert.append(text);wrap.append(alert);
    }
    return wrap;
  }
  const previews=new Map(),downloads=new Set();let generation=0,activeLoads=0;
  function clear(){generation++;for(const controller of downloads)controller.abort();for(const value of previews.values())value.promise.then(item=>item&&URL.revokeObjectURL(item.url));previews.clear();document.querySelectorAll(".media-lightbox").forEach(el=>el.remove());}
  function room(bytes,slots=0){
    let used=[...previews.values()].reduce((sum,entry)=>sum+(entry.item?.size||0),0);
    for(const [key,entry] of previews){
      if(used+bytes<=64*1024*1024&&previews.size+slots<=40)break;
      if(entry.item&&![...entry.item.owners].some(owner=>owner.isConnected)){
        used-=entry.item.size;URL.revokeObjectURL(entry.item.url);previews.delete(key);
      }
    }
    return used+bytes<=64*1024*1024&&previews.size+slots<=40;
  }
  async function load(digest,api,owner){
    if(previews.has(digest)){
      const item=await previews.get(digest).promise;
      if(item){for(const old of item.owners)if(!old.isConnected)item.owners.delete(old);item.owners.add(owner);}return item;
    }
    if(!room(0,1))return null;
    const rev=generation;
    const entry={item:null,promise:null};
    const work=(async()=>{
      while(activeLoads>=3&&rev===generation)await new Promise(resolve=>setTimeout(resolve,50));
      if(rev!==generation||!owner.isConnected||!room(0))return null;
      activeLoads++;const controller=new AbortController();downloads.add(controller);
      try{
      const response=await api("media/"+digest+"?inline=1",undefined,{signal:controller.signal}),mime=response.headers.get("content-type")?.split(";")[0];
      if(!/^(image\/(jpeg|png|webp|gif)|audio\/(ogg|mpeg|mp4)|video\/mp4)$/.test(mime)){
        await response.body?.cancel();return null;
      }
      const limit=32*1024*1024;
      if(Number(response.headers.get("content-length"))>limit){await response.body?.cancel();return null;}
      const reader=response.body.getReader(),chunks=[];let size=0;
      try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit){await reader.cancel();return null;}chunks.push(value);}}finally{reader.releaseLock();}
      if(rev!==generation||!owner.isConnected||!room(size))return null;
      entry.item={url:URL.createObjectURL(new Blob(chunks,{type:mime})),mime,size,owners:new Set([owner])};
      return entry.item;
      }finally{downloads.delete(controller);activeLoads--;}
    })().catch(()=>null).then(item=>{if(!item&&previews.get(digest)===entry)previews.delete(digest);return item;});
    entry.promise=work;previews.set(digest,entry);
    return work;
  }
  function lightbox(url,digest,tr){
    const dialog=n("dialog","media-lightbox"),toolbar=n("div","review-tabs"),img=n("img"),close=n("button","secondary",tr("Close")),zoom=n("button","quiet",tr("Zoom"));
    img.src=url;img.alt=tr("Saved image");close.type=zoom.type="button";
    toolbar.append(n("code","", "SHA-256 · "+digest),zoom,close);dialog.append(toolbar,img);document.body.append(dialog);
    close.addEventListener("click",()=>dialog.close());zoom.addEventListener("click",()=>dialog.classList.toggle("zoomed"));
    dialog.addEventListener("close",()=>dialog.remove());dialog.addEventListener("click",e=>{if(e.target===dialog)dialog.close();});dialog.showModal();close.focus();
  }
  function attachment(media,{api,download,busy,tr}){
    const digest=media.sha256||media.media_sha256,wrap=n("div","review-media"),area=n("div","review-preview"),actions=n("div","review-media-actions");
    const preview=n("button","quiet small",tr("Preview")),save=n("button","quiet small",tr("↓ Download preserved attachment"));preview.type=save.type="button";
    actions.append(preview,save);wrap.append(area,actions);const rev=generation;
    preview.addEventListener("click",()=>busy(preview,async()=>{
      const item=await load(digest,api,wrap);if(rev!==generation||!wrap.isConnected)return;
      if(!item){area.replaceChildren(n("p","hint",tr("Preview unavailable. Download the preserved file.")));return;}
      const tag=item.mime.startsWith("image/")?"img":item.mime.startsWith("audio/")?"audio":"video",el=n(tag);
      el.src=item.url;if(tag==="img"){
        el.alt=media.name||tr("Saved image");const open=n("button","review-image-button");open.type="button";open.setAttribute("aria-label",tr("Zoom"));open.append(el);open.addEventListener("click",()=>lightbox(item.url,digest,tr));area.replaceChildren(open);
      }else{el.controls=true;el.preload=tag==="audio"?"none":"metadata";area.replaceChildren(el);}
      preview.hidden=true;
    }));
    save.addEventListener("click",()=>busy(save,()=>download("media/"+digest,media.name||digest)));
    // Pictures are fetched only when their row comes into view; audio/video stay opt-in.
    if(/^image\//.test(media.mime_type||"")&&(media.size||0)<=8*1024*1024){
      const observer=new IntersectionObserver(entries=>{if(entries.some(e=>e.isIntersecting)){observer.disconnect();preview.click();}});
      observer.observe(wrap);setTimeout(()=>observer.disconnect(),60000);
    }
    return wrap;
  }
  window.addEventListener("tgwitness:lock",clear);
  window.TgWitnessReview={diff,compare,attachment,clear};
})();
