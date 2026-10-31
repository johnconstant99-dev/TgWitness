(() => {
  let context=null,controller=null,retry=null,flushTimer=null,cursor=0,pending=0,paused=false,connected=false,flushing=false,generation=0;
  const bars=[];
  function render(){
    if(!context)return;
    for(const {bar,toggle,fresh} of bars){
      if(!bar.isConnected)continue;
      toggle.textContent=context.tr(paused?"Live: paused":connected?"Live: on":"Live: reconnecting");
      toggle.setAttribute("aria-pressed",String(!paused));
      fresh.hidden=!pending;fresh.textContent=context.tr("{n} new events",{n:pending});
    }
  }
  function setup(parents){
    for(const parent of parents){
      if(!parent||bars.some(item=>item.bar.parentNode===parent))continue;
      const bar=document.createElement("div");bar.className="live-controls";
      const toggle=document.createElement("button"),fresh=document.createElement("button");
      toggle.type=fresh.type="button";toggle.className="quiet small live-toggle";fresh.className="secondary small live-new";fresh.hidden=true;
      toggle.addEventListener("click",()=>{paused=!paused;render();if(!paused)flush();});
      fresh.addEventListener("click",()=>flush(true));bar.append(toggle,fresh);parent.append(bar);bars.push({bar,toggle,fresh});
    }
  }
  async function flush(force=false){
    if(!context||flushing||!pending||(!force&&(paused||!context.canRefresh())))return;
    const rev=generation,count=pending;flushing=true;let success=false;
    try{await context.refresh({force});success=true;if(rev===generation)pending=Math.max(0,pending-count);}
    catch{}finally{if(rev===generation){flushing=false;render();
      if(pending&&!paused&&context?.canRefresh()){clearTimeout(flushTimer);flushTimer=setTimeout(()=>flush(),success?200:3000);}
    }}
  }
  function changed(events){
    pending+=events.length;render();clearTimeout(flushTimer);flushTimer=setTimeout(()=>flush(),200);
  }
  async function connect(rev){
    if(!context||rev!==generation||document.hidden||controller)return;
    const current=context,ctrl=new AbortController();controller=ctrl;
    try{
      const response=await current.api("stream?after="+cursor,undefined,{signal:ctrl.signal});
      if(rev!==generation||controller!==ctrl){await response.body?.cancel();return;}
      connected=true;render();const reader=response.body.getReader(),decoder=new TextDecoder();let buffer="";
      try{for(;;){
        const {value,done}=await reader.read();if(done||rev!==generation||controller!==ctrl)break;
        buffer=(buffer+decoder.decode(value,{stream:true})).replace(/\r\n/g,"\n");if(buffer.length>262144)throw new Error("Stream frame too large");
        let end;
        while((end=buffer.indexOf("\n\n"))!==-1){
          const block=buffer.slice(0,end);buffer=buffer.slice(end+2);
          if(block.includes("event: access-ended")){stop();current.accessEnded();return;}
          const data=block.split("\n").filter(line=>line.startsWith("data: ")).map(line=>line.slice(6)).join("\n");
          if(!data)continue;
          const events=JSON.parse(data).filter(event=>Number.isSafeInteger(event.seq)&&event.seq>cursor);
          if(events.length){cursor=events.at(-1).seq;changed(events);}
        }
      }}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
    }catch(error){if(error.status===401||error.status===403){if(rev===generation){stop();current.accessEnded();}return;}}
    finally{if(rev===generation&&context&&controller===ctrl){controller=null;connected=false;render();if(!document.hidden)retry=setTimeout(()=>connect(rev),3000);}}
  }
  function stop(){generation++;controller?.abort();controller=null;clearTimeout(retry);clearTimeout(flushTimer);context=null;pending=0;connected=false;flushing=false;for(const b of bars)b.bar.hidden=true;}
  function start(ctx){
    setup(ctx.hosts||[]);
    if(context?.key===ctx.key){context=ctx;for(const b of bars)b.bar.hidden=false;render();return;}
    stop();context=ctx;cursor=ctx.head||0;paused=false;for(const b of bars)b.bar.hidden=false;render();connect(generation);
  }
  document.addEventListener("visibilitychange",()=>{if(!context)return;if(document.hidden){controller?.abort();controller=null;connected=false;clearTimeout(retry);render();}else{clearTimeout(retry);connect(generation);}});
  document.addEventListener("selectionchange",()=>{if(!window.getSelection()?.toString())flush();});
  document.addEventListener("scroll",()=>flush(),true);
  window.addEventListener("tgwitness:lock",stop);
  window.TgWitnessLive={start,stop,active:()=>!!context,flush};
})();
