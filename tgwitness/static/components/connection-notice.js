/** Retry only a status read. Failed mutations are never replayed automatically. */
export function createConnectionNotice({host,tr,retry,active}) {
  const box=document.createElement('div'),message=document.createElement('span'),button=document.createElement('button');
  box.id='panel-connection-notice';box.className='panel-connection-notice';box.hidden=true;box.setAttribute('role','status');
  button.type='button';button.className='quiet';button.textContent=tr('Retry now');
  box.append(message,button);host.append(box);
  let timer=null,version=0,request=false;
  function schedule() {
    clearTimeout(timer);timer=null;
    if(!box.hidden&&active()&&!document.hidden)timer=setTimeout(check,5000);
  }
  async function check() {
    if(request||!active()||document.hidden)return;
    const mine=version;request=true;button.disabled=true;
    try{await retry();if(mine===version)clear();}
    catch{if(mine===version)schedule();}
    finally{if(mine===version){request=false;button.disabled=false;}}
  }
  function fail() {
    if(!active())return;
    box.hidden=false;message.textContent=tr('Panel unavailable. Retrying the status check in 5 seconds.');schedule();
  }
  function clear() {version++;request=false;clearTimeout(timer);timer=null;box.hidden=true;button.disabled=false;}
  button.addEventListener('click',()=>{clearTimeout(timer);void check();});
  document.addEventListener('visibilitychange',()=>{if(document.hidden){clearTimeout(timer);timer=null;}else schedule();});
  return {fail,clear};
}
