export function createSystemLog({root,tr,json,getState,getSession,options,formatTime,toast}) {
  const find=id=>root.querySelector('#'+id), listeners=new AbortController();
  let after=0,request=0,session=getSession();
  const active=()=>getState().view==='system-log'&&!!getState().me?.admin;
  function resetSession(){session=getSession();after=0;request++;find('access-console').replaceChildren();find('console-state').textContent='';}
  async function load(){
    if(!active())return;
    if(session!==getSession())resetSession();
    const started=getSession(),serial=++request,view=options(),pre=find('access-console');
    const result=await json('access/console?after='+after,undefined,{root:true,...view});
    if(!active()||started!==getSession()||serial!==request||view.signal?.aborted)return;
    if(result.lines.length&&result.lines[0].n<=after)pre.replaceChildren();
    for(const line of result.lines){
      const item=root.ownerDocument.createElement('span');item.className='console-line '+line.level.toLowerCase();
      item.textContent=formatTime(line.at)+' '+line.level.padEnd(7)+' '+line.text+'\n';pre.append(item);
    }
    while(pre.childElementCount>3000)pre.firstElementChild.remove();
    after=result.last;
    find('console-state').textContent=tr('{n} recent log lines',{n:pre.childElementCount});
    if(result.lines.length&&find('console-follow').checked)pre.scrollTop=pre.scrollHeight;
  }
  find('console-refresh').addEventListener('click',()=>load().catch(error=>{if(error.name!=='StaleView')toast(error.message,true);}),{signal:listeners.signal});
  return {load,enter:load,leave(){request++;},resetSession,destroy(){listeners.abort();resetSession();}};
}
