// View roots retain their own nodes and listeners while detached from the document.
export function viewReferences(root){
  return {
    root,
    byId(id){return root.id===id?root:root.querySelector("#"+CSS.escape(id));},
    query(selector){return root.querySelector(selector);},
    queryAll(selector){return [...root.querySelectorAll(selector)];},
  };
}

export function createViewHost({getSession=()=>({}),onError=error=>console.error(error)}={}){
  const entries=new Map();
  let active=null,generation=0,status=null,disposed=false;
  function leave(entry){
    entry.request?.abort();entry.request=null;entry.unlink?.();entry.unlink=null;
    if(active===entry){
      try{entry.controller.leave?.();}catch(error){onError(error);}
      active=null;
    }
    entry.root.hidden=true;delete entry.root.dataset.loading;entry.root.removeAttribute("aria-busy");entry.root.remove();
  }
  function register(name,root,controller={}){
    if(disposed||entries.has(name)||!root?.parentNode)throw new Error("View registration requires a unique name and an attached root.");
    const anchor=document.createComment("view:"+name);root.before(anchor);
    const entry={name,root,anchor,controller,refs:viewReferences(root),mounted:false,request:null,unlink:null,context:null};
    entries.set(name,entry);return entry.refs;
  }
  async function activate(name,{params={},signal}={}){
    const entry=entries.get(name);
    if(disposed||!entry)throw new Error("Unknown view: "+name);
    // A cancelled navigation must not disturb the screen the person is using.
    if(signal?.aborted)return false;
    const ticket=++generation;
    if(active&&active!==entry)leave(active);
    for(const other of entries.values())if(other!==entry&&other.root.isConnected)leave(other);
    entry.request?.abort();entry.unlink?.();
    const request=new AbortController();entry.request=request;
    if(signal){
      const abort=()=>request.abort();signal.addEventListener("abort",abort,{once:true});
      entry.unlink=()=>signal.removeEventListener("abort",abort);if(signal.aborted)request.abort();
    }
    active=entry;entry.anchor.after(entry.root);entry.root.hidden=false;
    const session=Object.freeze({...getSession()});
    const current=()=>!disposed&&!request.signal.aborted&&ticket===generation&&active===entry;
    entry.context={signal:request.signal,session,params,current};
    entry.root.dataset.loading="true";entry.root.setAttribute("aria-busy","true");
    try{
      if(!entry.mounted){entry.controller.mount?.(entry.root);entry.mounted=true;}
      if(status)updateStatus(status);
      await entry.controller.enter?.(entry.context);
      return current();
    }catch(error){
      if(!current()||error?.name==="AbortError")return false;
      if(!entry.mounted)leave(entry);
      throw error;
    }finally{if(current()){delete entry.root.dataset.loading;entry.root.removeAttribute("aria-busy");}}
  }
  function updateStatus(next){
    status=next;if(disposed||!active||active.request?.signal.aborted)return;
    const entry=active,ticket=generation;
    try{
      const work=entry.controller.updateStatus?.(next,entry.context);
      work?.catch?.(error=>{if(!disposed&&active===entry&&ticket===generation)onError(error);});
    }catch(error){onError(error);}
  }
  function resetSession(){
    generation++;status=null;
    for(const entry of entries.values()){
      leave(entry);
      try{entry.controller.resetSession?.();}catch(error){onError(error);}
    }
  }
  function destroy(){
    if(disposed)return;resetSession();disposed=true;generation++;
    for(const entry of entries.values()){
      try{entry.controller.destroy?.();}catch(error){onError(error);}
      entry.anchor.remove();
    }
    entries.clear();
  }
  return {register,activate,updateStatus,resetSession,destroy,
    get active(){return active?.name||null;},
    references(name){return entries.get(name)?.refs||null;},
    isMounted(name){return !!entries.get(name)?.root.isConnected;},
  };
}
